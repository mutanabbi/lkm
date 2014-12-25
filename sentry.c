#include <linux/socket.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/types.h>
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
            printk(KERN_DEBUG "Found the sys_call_table!!!\n");
            return (void **)ptr;
        }
    }
    return NULL;
}


// a pointer to store an original syscall
asmlinkage long (*origin_sys_execve)(
    const char __user *filename
  , const char __user *const __user *argv
  , const char __user *const __user *envp
);


bool foo(const char* filename);


asmlinkage long my_sys_execve(
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
    is_permitted = foo(filename);
    // printk("argv: %s\n", argv);
    // printk("envp: %s\n", envp);
    printk(is_permitted ? "Permit\n" : "Deny\n");
    ret = is_permitted ? origin_sys_execve(filename, argv, envp) : -1;
    printk("My own execve stop\n");
    return ret;
}


int32_t orig_offset = 0;
void* callq_arg_addr = 0;


bool foo(const char* filename)
{
    #define MAX 100
    #define SOCK_PATH "/tmp/usocket"

    struct socket *sock = 0;

    int retval;
    char buf[MAX] = {0};
    unsigned long len = 0;

    struct sockaddr_un addr;
    struct msghdr msg;
    struct iovec iov;
    mm_segment_t oldfs;

    strncpy(buf, filename, MAX);

    retval = sock_create(AF_UNIX, SOCK_STREAM, 0, &sock);
    printk("socket create rc: %d\n", retval);
    if (retval < 0)
        return false;

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
    len = strnlen(buf, MAX);
    len = len < MAX ? len + 1 : MAX;

    msg.msg_name = 0;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_iov->iov_base = buf;
    msg.msg_iov->iov_len = len;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    oldfs = get_fs();
    set_fs(get_ds());

    retval = sock_sendmsg(sock, &msg, len);
    printk("socket send rc: %d\n", retval);
    if (retval < 0)
        return false;

    // recvmsg
    memset(&buf, 0, sizeof(buf));
    msg.msg_iov->iov_len = MAX;
    retval = sock_recvmsg(sock, &msg, MAX, 0);
    printk("socket receive rc: %d\n", retval);
    if (retval < 0)
        return false;

    set_fs(oldfs);

    buf[MAX - 1] = 0;
    printk("received: %s\n", buf);

    sock_release(sock);
    return 0 == strncmp("Y", buf, MAX);
}


// Store a pointer to original syscall and replace it with my own one
int init_module(void)
{
    int ret = 0;
    int32_t offset = 0;
    unsigned long addr;
    unsigned long cr0;
    //const char* p = 0;
    unsigned long n = 0;
    void* callq_addr = 0;
    void* sys_execve_addr = 0;
    union {
        char buf[4];
        int32_t val;
    } a;
    void* stub_execve = 0;
    void** sys_call_table;

    a.val = 0;

    sys_call_table = find_sys_call_table();

    printk("__NR_close: %d\n", __NR_close);
    printk("execv index: %d\n", __NR_execve);
    printk("sys_call_table address: %pK\n", sys_call_table);
    printk("stub_execv address: %pK\n", sys_call_table[__NR_execve]);
    printk("sizeof(unsigned long): %lu\n", sizeof(unsigned long));
    printk("sizeof(void*): %lu\n", sizeof(void*));
    stub_execve = sys_call_table[__NR_execve];

    /* dirty naive callq lookup
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
        printk(KERN_DEBUG "Cannot find callq instrction by expected offset\n");
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

    printk("my_sys_execve address: %pK\n", my_sys_execve);
    offset = (void*)my_sys_execve - (callq_addr + 5);
    printk("my_sys_execve offset: %x (%*ph)\n", offset, (int)sizeof(offset), &offset);
    printk("my_sys_execve address (doublecheck): %pK\n", callq_addr + 5 + offset);

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
