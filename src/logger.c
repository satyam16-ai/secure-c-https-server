#include "../include/https_server.h"
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>

static FILE *access_log = NULL;
static FILE *error_log = NULL;
static int debug_mode = 0;

static void log_time(FILE *fp)
{
    time_t now = time(NULL);
    struct tm tm_info;
    char buf[32];
    localtime_r(&now, &tm_info);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    fprintf(fp, "[%s] ", buf);
}

static void rotate_log_file(FILE **fp, const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && st.st_size >= LOG_ROTATE_SIZE)
    {
        char new_path[MAX_PATH_SIZE + 64];
        time_t now = time(NULL);
        struct tm tm_info;
        localtime_r(&now, &tm_info);
        strftime(new_path, sizeof(new_path), "%Y%m%d%H%M%S", &tm_info);
        char rotated_path[MAX_PATH_SIZE + 64];
        snprintf(rotated_path, sizeof(rotated_path), "%s.%s", path, new_path);
        fclose(*fp);
        rename(path, rotated_path);
        *fp = fopen(path, "a");
    }
}

void logger_rotate(void)
{
    if (access_log)
        rotate_log_file(&access_log, "logs/access.log");
    if (error_log)
        rotate_log_file(&error_log, "logs/error.log");
}

void logger_init(const char *log_dir)
{
    char access_path[MAX_PATH_SIZE], error_path[MAX_PATH_SIZE];
    snprintf(access_path, sizeof(access_path), "%s/access.log", log_dir);
    snprintf(error_path, sizeof(error_path), "%s/error.log", log_dir);
    access_log = fopen(access_path, "a");
    error_log = fopen(error_path, "a");
    if (!access_log || !error_log)
    {
        fprintf(stderr, "Failed to open log files in %s\n", log_dir);
    }
}

void logger_cleanup(void)
{
    if (access_log)
        fclose(access_log);
    if (error_log)
        fclose(error_log);
    access_log = NULL;
    error_log = NULL;
}

void logger_access(const char *format, ...)
{
    if (!access_log)
        return;
    logger_rotate();
    log_time(access_log);
    va_list args;
    va_start(args, format);
    vfprintf(access_log, format, args);
    va_end(args);
    fprintf(access_log, "\n");
    fflush(access_log);
}

void logger_error(const char *format, ...)
{
    if (!error_log)
        return;
    logger_rotate();
    log_time(error_log);
    va_list args;
    va_start(args, format);
    vfprintf(error_log, format, args);
    va_end(args);
    fprintf(error_log, "\n");
    fflush(error_log);
}

void logger_debug(const char *format, ...)
{
    if (!error_log)
        return;
    if (!debug_mode)
        return;
    logger_rotate();
    log_time(error_log);
    va_list args;
    va_start(args, format);
    vfprintf(error_log, format, args);
    va_end(args);
    fprintf(error_log, "\n");
    fflush(error_log);
    // Also print to stderr if debug mode
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}

void logger_set_debug(int enable)
{
    debug_mode = enable;
}
