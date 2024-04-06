#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <malloc.h>
#include <stdbool.h>
#include <fcntl.h>
#include <string.h>
#include <sys/utsname.h>

const char* KALLSYMS_PATH = "/proc/kallsyms";

enum parse_kallsyms_error {
    PARSE_KALLSYMS_SUCCES,
    PARSE_KALLSYMS_FOPEN_ERROR,
    PARSE_KALLSYMS_ALLOC_ERROR,
    PARSE_KALLSYMS_DATA_ERROR,
    PARSE_KALLSYMS_READ_ERROR
};

typedef struct kallsym {
    char     name_symbol[512];
    char     type;
    uint64_t address;
} kallsym;

typedef struct parse_kallsyms_result {
    enum parse_kallsyms_error error;
    int                       value;
} parse_kallsyms_result;

parse_kallsyms_result parse_kallsyms_file(kallsym** array_pointer, int fd_kallsyms)
{
    int lines = 0;
    int retval = 0;
    kallsym* sym_list = NULL;
    parse_kallsyms_result result = {PARSE_KALLSYMS_SUCCES, 0};

    FILE* file_kallsyms = fdopen(fd_kallsyms, "r");
    if (file_kallsyms == NULL)
    {
        result.error = PARSE_KALLSYMS_FOPEN_ERROR;
        result.value = errno;
        return result;
    }

    while (!feof(file_kallsyms))
    {
        int ch = fgetc(file_kallsyms);
        if (ch == '\t')
            break;
        else if (ch == '\n')
            lines++;
    }
    rewind(file_kallsyms);

    if (lines < 1)
    {
        result.error = PARSE_KALLSYMS_DATA_ERROR;
        return result;
    }

    sym_list = (kallsym*) malloc(lines * sizeof(kallsym));
    if (sym_list == NULL)
    {
        result.error = PARSE_KALLSYMS_ALLOC_ERROR;
        result.value = errno;
        return result;
    }

    for (int i = 0; i < lines && !feof(file_kallsyms); ++i)
    {
        uint64_t* address = &sym_list[i].address;
        char* type = &sym_list[i].type;
        char* name_symbol = sym_list[i].name_symbol;

        retval = fscanf(file_kallsyms, "%lx %c %s", address, type, name_symbol);
        if (retval < 3)
        {
            free(sym_list);
            result.error = PARSE_KALLSYMS_READ_ERROR;
            result.value = errno;
            return result;
        }
    }

    *array_pointer = sym_list;
    result.value = lines;
    return result;
}


static inline kallsym* find_symbol_from_kallsyms(kallsym* kallsyms, const int kallsyms_lenght, const char* symbol_name)
{
    for (int i = 0; i < kallsyms_lenght; ++i)
    {
        if (!strcmp(kallsyms[i].name_symbol, symbol_name))
            return &kallsyms[i];
    }

    return NULL;
}

int main()
{
    int proc_kallsyms_fd = 0;
    int kallsyms_lenght = 0;
    int retval = 0;

    const char* CONFIG_DEBUG_SPINLOCK = NULL;
    const char* CONFIG_DEBUG_LOCK_ALLOC = NULL;
    const char* CONFIG_LOCK_STAT = NULL;
    const char* CONFIG_MUTEX_SPIN_ON_OWNER = NULL;
    const char* CONFIG_DEBUG_MUTEXES = NULL;

    kallsym* kallsyms = NULL;
    kallsym* kallsym_text = NULL;
    kallsym* kallsym_startup_xen = NULL;
    kallsym* kallsym_rwlock_init = NULL;            //CONFIG_DEBUG_SPINLOCK
    kallsym* kallsym_lockdep_sys_exit_thunk = NULL; //CONFIG_DEBUG_LOCK_ALLOC
    kallsym* kallsym_lock_contended = NULL;         //CONFIG_LOCK_STAT
    kallsym* kallsym_mutex_spin_on_owner = NULL;    //CONFIG_MUTEX_SPIN_ON_OWNER
    kallsym* kallsym_mutex_destroy = NULL;          //CONFIG_DEBUG_MUTEXES
    kallsym* kallsym_kernfs_pr_cont_buf = NULL;
    kallsym* kallsym_clk_change_rate = NULL;
    kallsym* kallsym_get_task_cred = NULL;
    kallsym* kallsym_find_task_by_vpid = NULL;
    kallsym* kallsym_memcpy = NULL;

    parse_kallsyms_result result;

    struct utsname linux_info;

    proc_kallsyms_fd = open(KALLSYMS_PATH, O_RDONLY);
    if (proc_kallsyms_fd < 0)
    {
        fprintf(stderr, "Error open %s, %s \n", KALLSYMS_PATH, strerror(errno));
        goto error_kallsyms_not_exist;
    }


    result = parse_kallsyms_file(&kallsyms, proc_kallsyms_fd);
    if (result.error)
    {
        fprintf(stderr, "Error parse %s, error num %d \n", KALLSYMS_PATH, result.error);
        goto error_parse_kallsyms;
    }

    kallsyms_lenght = result.value;

    kallsym_rwlock_init             = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "rwlock_init");
    kallsym_lockdep_sys_exit_thunk  = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "lockdep_sys_exit_thunk");
    kallsym_lock_contended          = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "lock_contended");
    kallsym_mutex_spin_on_owner     = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "mutex_spin_on_owner");
    kallsym_mutex_destroy           = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "mutex_destroy");

    kallsym_text                    = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "_text");
    if (kallsym_text == NULL)
    {
        fprintf(stderr, "Error find text \n");
        goto error_find_text;
    }

    kallsym_startup_xen             = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "startup_xen");
    if (kallsym_startup_xen == NULL)
    {
        fprintf(stderr, "Error find startup_xen \n");
        goto error_find_startup_xen;
    }

    kallsym_kernfs_pr_cont_buf      = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "kernfs_pr_cont_buf");
    if (kallsym_startup_xen == NULL)
    {
        fprintf(stderr, "Error find kernfs_pr_cont_buf \n");
        goto error_find_kernfs_pr_cont_buf;
    }

    kallsym_clk_change_rate         = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "clk_change_rate");
    if (kallsym_startup_xen == NULL)
    {
        fprintf(stderr, "Error find clk_change_rate \n");
        goto error_find_clk_change_rate;
    }

    kallsym_get_task_cred           = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "get_task_cred");
    if (kallsym_startup_xen == NULL)
    {
        fprintf(stderr, "Error find get_task_cred \n");
        goto error_find_get_task_cred;
    }

    kallsym_find_task_by_vpid       = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "find_task_by_vpid");
    if (kallsym_startup_xen == NULL)
    {
        fprintf(stderr, "Error find find_task_by_vpid \n");
        goto error_find_task_by_vpid;
    }

    kallsym_memcpy                  = find_symbol_from_kallsyms(kallsyms, kallsyms_lenght, "memcpy");
    if (kallsym_startup_xen == NULL)
    {
        fprintf(stderr, "Error find memcpy \n");
        goto error_find_memcpy;
    }

    retval = uname(&linux_info);
    if (retval != 0)
    {
        fprintf(stderr, "Error get linux info, errno -> %s \n", strerror(errno));
        goto error_uname;
    }

    CONFIG_DEBUG_SPINLOCK        = kallsym_rwlock_init            != NULL ? "true" : "false";
    CONFIG_DEBUG_LOCK_ALLOC      = kallsym_lockdep_sys_exit_thunk != NULL ? "true" : "false";
    CONFIG_LOCK_STAT             = kallsym_lock_contended         != NULL ? "true" : "false";
    CONFIG_MUTEX_SPIN_ON_OWNER   = kallsym_mutex_spin_on_owner    != NULL ? "true" : "false";
    CONFIG_DEBUG_MUTEXES         = kallsym_mutex_destroy          != NULL ? "true" : "false";

    printf("{\"distro_name\", \"%s\", %s, %s, %s, %s, %s, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx} \n",
           linux_info.release,
           CONFIG_DEBUG_SPINLOCK,
           CONFIG_DEBUG_LOCK_ALLOC,
           CONFIG_LOCK_STAT,
           CONFIG_MUTEX_SPIN_ON_OWNER,
           CONFIG_DEBUG_MUTEXES,
           kallsym_startup_xen->address        - kallsym_text->address,
           kallsym_kernfs_pr_cont_buf->address - kallsym_text->address,
           kallsym_clk_change_rate->address    - kallsym_text->address,
           kallsym_find_task_by_vpid->address  - kallsym_text->address,
           kallsym_get_task_cred->address      - kallsym_text->address,
           kallsym_memcpy->address             - kallsym_text->address);

    error_uname:

    error_find_memcpy:

    error_find_task_by_vpid:

    error_find_get_task_cred:

    error_find_clk_change_rate:

    error_find_kernfs_pr_cont_buf:

    error_find_startup_xen:

    error_find_text:

    free(kallsyms);
    error_parse_kallsyms:

    error_kallsyms_not_exist:

    return 0;
}
