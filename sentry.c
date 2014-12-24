#include <linux/socket.h>
#include <net/sock.h>
#include <uapi/linux/un.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
//#include <linux/string.h>
#include <asm/cacheflush.h>
#include <linux/types.h>

#define CR0_WP 0x00010000   // Write Protect Bit (CR0:16)

MODULE_LICENSE("GPL");

#define SOCK_PATH   "/tmp/usocket"

struct socket *sock = NULL;


/* Экспортируем таблицу системных вызовов */
//extern void *sys_call_table[];
void** sys_call_table;

void **find_sys_call_table(void) {
    void* ptr = sys_close;

    for (;
         ptr < (void*)&loops_per_jiffy;
         ++ptr
      )
    {
        if (((void**)ptr)[__NR_close] == sys_close)
        {
            printk(KERN_DEBUG "Found the sys_call_table!!!\n");
            return (void **)ptr;
        }
    }
    return NULL;
}

//unsigned long **find_sys_call_table() {
//    unsigned long ptr;
//    unsigned long *p;
//
//    for (ptr = (unsigned long)sys_close;
//         ptr < (unsigned long)&loops_per_jiffy;
//         ptr += sizeof(void *)) {
//        p = (unsigned long *)ptr;
//
//        if (p[__NR_close] == (unsigned long)sys_close) {
//            printk(KERN_DEBUG "Found the sys_call_table!!!\n");
//            return (unsigned long **)p;
//        }
//    }
//    return NULL;
//}

/* Определим указатель для сохранения оригинально вызова */
//int (*orig_mkdir)(const char *path);

asmlinkage long (*origin_sys_execve)(const char __user *filename,
    const char __user *const __user *argv,
    const char __user *const __user *envp);

void foo(const char* filename);

asmlinkage long my_sys_execve(const char __user *filename,
    const char __user *const __user *argv,
    const char __user *const __user *envp)
{

    long ret = 0;
    printk("My own execve start\n");
    printk("origin execv address: %pK\n", origin_sys_execve);
    printk("filename: %s\n", filename);
    foo(filename);
    // printk("argv: %s\n", argv);
    // printk("envp: %s\n", envp);
    ret = origin_sys_execve(filename, argv, envp);
    printk("My own execve stop\n");
    return ret;
}

int32_t orig_offset = 0;
void* callq_arg_addr = 0;


void foo(const char* filename)
{
  #define MAX 100
  int retval;
  char str[MAX];

  struct sockaddr_un addr;
  struct msghdr msg;
  struct iovec iov;
  mm_segment_t oldfs;

  strcpy(str, filename);

  retval = sock_create(AF_UNIX, SOCK_STREAM, 0, &sock);
  printk("socket create rc: %d\n", retval);

  // connect
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, SOCK_PATH);

  retval = sock->ops->connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
  printk("socket connect rc: %d\n", retval);

  // recvmsg

  memset(&msg, 0, sizeof(msg));
  memset(&iov, 0, sizeof(iov));

  msg.msg_name = 0;
  msg.msg_namelen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_iov->iov_base = str;
  msg.msg_iov->iov_len = strlen(str)+1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  oldfs = get_fs();
  set_fs(get_ds());

  retval = sock_sendmsg(sock, &msg, strlen(str) + 1);
  printk("socket send rc: %d\n", retval);
  retval = sock_recvmsg(sock, &msg, strlen(str) + 1, 0);
  printk("socket receive rc: %d\n", retval);

  set_fs(oldfs);

  // release socket
  sock_release(sock);
}


/* Во время инициализации модуля сохраняем указатель на оригинальный
   вызов и производим замену системного вызова */
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

    a.val = 0;

    //unsigned long i = 0;

    sys_call_table = find_sys_call_table();

    printk("__NR_close: %d\n", __NR_close);
    printk("execv index: %d\n", __NR_execve);
    printk("sys_call_table address: %pK\n", sys_call_table);
    printk("stub_execv address: %pK\n", sys_call_table[__NR_execve]);
    printk("sizeof(unsigned long): %lu\n", sizeof(unsigned long));
    printk("sizeof(void*): %lu\n", sizeof(void*));
    //printk("sys_execv address: %pK\n", sys_execve);
    //origin_sys_execve = sys_execve;
    stub_execve = sys_call_table[__NR_execve];
    //p = (const char*)stub_execve;
    //while (*p++ != (char)0xe8 && n++ < 300);
    //printk("opcode address: %pK\n", p);
    //printk("counter: %lu\n", n);
    //printk("opcode: %*ph\n", 1, p);
    //printk("stub_execve code: %*ph\n", 100, (const char*)origin_sys_execve + 100);
    callq_addr = stub_execve + 100;
    if (*(const char*)callq_addr != (char)0xe8)
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

    //addr = (unsigned long)sys_call_table;
    addr = (unsigned long)callq_arg_addr;
    ret = set_memory_rw(PAGE_ALIGN(addr) - PAGE_SIZE, 3);

    if (ret)
        printk(KERN_DEBUG "Cannot set the memory to rw (%d) at addr %16lX\n", ret, PAGE_ALIGN(addr) - PAGE_SIZE);
    else
        printk(KERN_DEBUG "3 pages set to rw");

//    sys_call_table[__NR_execve] = my_sys_execve;
    memcpy(callq_arg_addr, &offset, sizeof(offset));
    write_cr0(cr0);
    printk("sys_execv replaced\n");
    return 0;
}

/* При выгрузке восстанавливаем оригинальный вызов */

void cleanup_module(void)
{
    unsigned long cr0;
    cr0 = read_cr0();
    write_cr0(cr0 & ~CR0_WP);
    memcpy(callq_arg_addr, &orig_offset, sizeof(orig_offset));
//    sys_call_table[__NR_execve] = (void*)origin_sys_execve;
    write_cr0(cr0);
    printk("sys_mkdir moved back\n");
}
