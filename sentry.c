#include <linux/socket.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/types.h>
#include <linux/namei.h>
#include <net/sock.h>
#include <uapi/linux/un.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");

#define CR0_WP 0x00010000   // Write Protect Bit (CR0:16)


void **find_sys_call_table(void) {
    void* ptr = sys_close;
    for ( ; ptr < (void*)&loops_per_jiffy; ++ptr)
    {
        if (sys_close == ((void**)ptr)[__NR_close])
        {
            printk(KERN_DEBUG "sys_call_table was founded!\n");
            return (void **)ptr;
        }
    }
    return NULL;
}


// A pointer for storing an original syscall
asmlinkage long (*origin_sys_execve)(
    const char __user *filename
  , const char __user *const __user *argv
  , const char __user *const __user *envp
);


bool ask(const char* filename);
bool connect_and_ask(struct socket*, const char* filename);
bool path_lookup_and_ask(const char* filename);


asmlinkage long proxy_sys_execve(
    const char __user *filename
  , const char __user *const __user *argv
  , const char __user *const __user *envp
  )
{
    long ret = 0;
    bool is_permitted = false;

    printk("My own execve start\n");
    printk("origin execv address: %pK\n", origin_sys_execve);
    printk("filename: %s\n", filename);

    is_permitted = path_lookup_and_ask(filename);
    printk(is_permitted ? "Permit\n" : "Deny\n");
    ret = is_permitted ? origin_sys_execve(filename, argv, envp) : -1;
    printk("My own execve stop\n");
    return ret;
}


int32_t orig_offset = 0;
void* callq_arg_addr = NULL;


// Searh an absolute path by a filename and delegate call to connect_and_ask()
// also this function is "RAII" wrapper for managing memory for a buffer,
// what contains an absolute path name
bool path_lookup_and_ask(const char* filename)
{
    bool ret = false;
    int retval = 0;

    struct path abs = {0};
    char* dentry_buf = NULL;
    const char* abspath = NULL;

    // get absolute and canonical path
    retval = user_path(filename, &abs);

    if (retval == -ENOENT)
    {
        printk("can't find file: %s\n", filename);
        return false;
    }
    if (retval)
    {
        printk("unexpected error during file lookup: %s\n", filename);
        return false;
    }

    dentry_buf = (char*)__get_free_page(GFP_USER);

    abspath = dentry_path_raw(abs.dentry, dentry_buf, PAGE_SIZE);
    if (ERR_PTR(-ENAMETOOLONG) != abspath)
    {
        printk("absolute path: %s\n", abspath);
        ret = ask(abspath);                                 // ask permissions from user space daemon
    }
    else
        printk("can't find absolute path. Looks like buffer (mem page size) isnt' big enough.\n");

    free_page((unsigned long)dentry_buf);
    return ret;
}


// "RAII" wrapper for managing socket creation/releasing
bool ask(const char* filename)
{
    int retval = 0;
    struct socket* sock = NULL;
    bool ret = false;

    // communication
    retval = sock_create(AF_UNIX, SOCK_STREAM, 0, &sock);
    printk("socket create rc: %d\n", retval);
    if (retval < 0)
        return false;

    ret = connect_and_ask(sock, filename);

    sock_release(sock);
    return ret;
}


// A lot of exit points in this function below. No resources acquisition, please.
bool connect_and_ask(struct socket* sock, const char* filename)
{
    #define MAX 100
    #define SOCK_PATH "/tmp/usocket"

    int retval = 0;
    char buf[MAX] = {0};
    unsigned long len = 0;

    struct sockaddr_un addr;
    struct msghdr msg;
    struct iovec iov;
    mm_segment_t oldfs;

    // connect
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, UNIX_PATH_MAX);

    retval = sock->ops->connect(sock, (struct sockaddr *)&addr, sizeof(addr) - 1, 0);
    printk("socket connect rc: %d\n", retval);
    if (retval < 0)
        return false;

    // sendmsg
    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    len = strlen(filename) + 1;

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_iov->iov_base = (char*)filename;                // Dirty cast here. But I intend just send a message.
                                                            // I hope, the kernel is smart ehough to not write to user buffer on sending :)
    msg.msg_iov->iov_len = len;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    // Damn! Resource acquisition. Be carefull. No exit points below!
    oldfs = get_fs();
    set_fs(get_ds());

    retval = sock_sendmsg(sock, &msg, len);
    printk("socket send rc: %d\n", retval);
    if (!retval < 0)
    {
        // recvmsg
        msg.msg_iov->iov_len = MAX;
        msg.msg_iov->iov_base = buf;                        // And here is over, writable buffer

        retval = sock_recvmsg(sock, &msg, MAX, 0);
        printk("socket receive rc: %d\n", retval);
    }

    set_fs(oldfs);                                          // Uff, we can use exit points again

    if (retval < 0)
        return false;

    buf[retval > 0 ? retval - 1 : 0] = 0;
    printk("received: %s\n", buf);

    return 0 == strncmp("Y", buf, MAX);
}


// Store a pointer to original syscall and replace it with my own one
int init_module(void)
{
    int ret = 0;
    int32_t offset = 0;
    unsigned long addr;
    unsigned long cr0;
    unsigned long n = 0;
    void* callq_addr = NULL;
    void* sys_execve_addr = NULL;
    union {
        char buf[4];
        int32_t val;
    } a;
    void* stub_execve = NULL;
    void** sys_call_table = NULL;

    a.val = 0;

    sys_call_table = find_sys_call_table();
    if (! sys_call_table)
    {
        printk("Can't find syscall table. Wrong kernel version? Check your System.map file.\n");
        return -1;
    }

    printk("__NR_close: %d\n", __NR_close);
    printk("execv index: %d\n", __NR_execve);
    printk("sys_call_table address: %pK\n", sys_call_table);
    printk("stub_execv address: %pK\n", sys_call_table[__NR_execve]);
    printk("sizeof(unsigned long): %lu\n", sizeof(unsigned long));
    printk("sizeof(void*): %lu\n", sizeof(void*));
    stub_execve = sys_call_table[__NR_execve];

    /* Dirty naive callq lookup. Just a possible workaround.
    p = (const char*)stub_execve;
    while ((const char)0xe8 != *p++ && n++ < 300);
    printk("opcode address: %pK\n", p);
    printk("counter: %lu\n", n);
    printk("opcode: %*ph\n", 1, p);
    printk("stub_execve code: %*ph\n", 100, (const char*)origin_sys_execve + 100);
    */

    // callq offset is 100. It's correct for 3.13.0, 3.17.1. For all 3.x.x I beleive
    // If it isn't, It's necessary to implement some primitive disassebler to find
    // callq insturction inside stub_execve
    //
    // I'm not pretty sure about 2.x.x kernel. May be It's just enought to rewrite a cell
    // of the syscall table there. So it's a different policy. Any way, right now I don't
    // have time to check it (and I don't have the binaries of 2.x.x kernel to disassemble).
    callq_addr = stub_execve + 100;
    if ((const char)0xe8 != *(const char*)callq_addr)
    {
        printk(KERN_DEBUG "Cannot find callq instruction at an expected offset\n");
        return -1;
    }
    callq_arg_addr = callq_addr + 1;
    for (n = 0; n < 4; ++n)
        a.buf[n] = *(const char*)(callq_arg_addr + n);
    printk("callq argument: %x (%*ph)\n", a.val, (int)sizeof(a.buf), a.buf);
    sys_execve_addr = callq_addr + 5 + a.val;
    printk("sys_execve address: %pK\n", sys_execve_addr);

    origin_sys_execve = sys_execve_addr;
    orig_offset = a.val;

    printk("proxy_sys_execve address: %pK\n", proxy_sys_execve);
    offset = (void*)proxy_sys_execve - (callq_addr + 5);
    printk("proxy_sys_execve offset: %x (%*ph)\n", offset, (int)sizeof(offset), &offset);
    printk("proxy_sys_execve address (doublecheck): %pK\n", callq_addr + 5 + offset);

    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);

    addr = (unsigned long)callq_arg_addr;
    ret = set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 3);

    if (ret)
        printk(KERN_DEBUG "Cannot set the memory to rw (%d) at addr %16lX\n", ret, PAGE_ALIGN(addr) - PAGE_SIZE);
    else
        printk(KERN_DEBUG "3 pages set to rw");

    memcpy(callq_arg_addr, &offset, sizeof(offset));
    write_cr0(cr0);
    printk("sys_execv replaced\n");
    return 0;
}


// restore original syscall at exit
void cleanup_module(void)
{
    unsigned long cr0;
    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    memcpy(callq_arg_addr, &orig_offset, sizeof(orig_offset));
    write_cr0(cr0);
    printk("sys_execv moved back\n");
}
