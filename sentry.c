#include <linux/module.h>
#include <linux/kernel.h>
//#include <sys/syscall.h>

/* Экспортируем таблицу системных вызовов */
extern void *sys_call_table[];

/* Определим указатель для сохранения оригинально вызова */
int (*orig_mkdir)(const char *path);

/* Создадим собственный системный вызов. Наш вызов ничего не делает,
   просто возвращает нулевое значение */
int own_mkdir(const char *path)
{
    return 0;
}

/* Во время инициализации модуля сохраняем указатель на оригинальный
   вызов и производим замену системного вызова */
int init_module(void)
{
    //orig_mkdir=sys_call_table[SYS_mkdir];
    //sys_call_table[SYS_mkdir]=own_mkdir;
    printk("sys_mkdir replaced\n");
    return(0);
}

/* При выгрузке восстанавливаем оригинальный вызов */

void cleanup_module(void)
{
    //sys_call_table[SYS_mkdir]=orig_mkdir;
    printk("sys_mkdir moved back\n");
}
