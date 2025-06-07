#ifndef HTTPS_SERVER_H
#define HTTPS_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

// Server configuration
#define DEFAULT_PORT 8080
#define DEFAULT_BACKLOG 128
#define MAX_CLIENTS 1024
#define BUFFER_SIZE 8192
#define MAX_HEADER_SIZE 4096
#define MAX_PATH_SIZE 1024
#define MAX_METHOD_SIZE 16
#define MAX_VERSION_SIZE 16
#define MAX_HEADER_COUNT 64
#define LOG_ROTATE_SIZE (5 * 1024 * 1024) // 5 MB

// HTTP methods
typedef enum
{
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_UNKNOWN
} http_method_t;

// HTTP version
typedef enum
{
    HTTP_1_0,
    HTTP_1_1,
    HTTP_UNKNOWN_VERSION
} http_version_t;

// HTTP status codes
typedef enum
{
    HTTP_200_OK = 200,
    HTTP_301_MOVED_PERMANENTLY = 301,
    HTTP_400_BAD_REQUEST = 400,
    HTTP_401_UNAUTHORIZED = 401,
    HTTP_403_FORBIDDEN = 403,
    HTTP_404_NOT_FOUND = 404,
    HTTP_405_METHOD_NOT_ALLOWED = 405,
    HTTP_500_INTERNAL_SERVER_ERROR = 500,
    HTTP_501_NOT_IMPLEMENTED = 501,
    HTTP_503_SERVICE_UNAVAILABLE = 503
} http_status_t;

// HTTP header structure
typedef struct
{
    char name[MAX_HEADER_SIZE / 2];
    char value[MAX_HEADER_SIZE / 2];
} http_header_t;

// HTTP request structure
typedef struct
{
    http_method_t method;
    http_version_t version;
    char path[MAX_PATH_SIZE];
    http_header_t headers[MAX_HEADER_COUNT];
    size_t header_count;
    char *body;
    size_t body_length;
} http_request_t;

// HTTP response structure
typedef struct
{
    http_status_t status;
    http_version_t version;
    http_header_t headers[MAX_HEADER_COUNT];
    size_t header_count;
    char *body;
    size_t body_length;
    int keep_alive;
} http_response_t;

// Client connection structure
typedef struct
{
    int socket;
    SSL *ssl;
    struct sockaddr_in addr;
    time_t last_activity;
    int keep_alive;
    char buffer[BUFFER_SIZE];
    size_t buffer_pos;
} client_t;

// Server configuration structure
typedef struct
{
    int port;
    char *cert_file;
    char *key_file;
    char *static_dir;
    char *log_dir;
    int max_clients;
    int backlog;
    int debug;
    char *auth_user;
    char *auth_pass;
} server_config_t;

// Thread pool structure
typedef struct
{
    pthread_t *threads;
    int thread_count;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    client_t **queue;
    int queue_size;
    int queue_count;
    int queue_head;
    int queue_tail;
    int shutdown;
} thread_pool_t;

// Function declarations

// server.c
int server_init(server_config_t *config);
int server_run(server_config_t *config);
void server_cleanup(void);

// ssl.c
int ssl_init(server_config_t *config);
void ssl_cleanup(void);
SSL_CTX *ssl_get_context(void);

// router.c
int router_init(void);
void router_cleanup(void);
int router_handle_request(http_request_t *req, http_response_t *resp);

// mime.c
const char *mime_get_type(const char *path);
void mime_init(void);

// thread_pool.c
thread_pool_t *thread_pool_create(int thread_count, int queue_size);
void thread_pool_destroy(thread_pool_t *pool);
int thread_pool_add_task(thread_pool_t *pool, client_t *client);

// logger.c
void logger_init(const char *log_dir);
void logger_cleanup(void);
void logger_access(const char *format, ...);
void logger_error(const char *format, ...);
void logger_debug(const char *format, ...);
void logger_rotate(void);

// utils.c
char *read_file(const char *path, size_t *size);
int is_directory(const char *path);
char *url_decode(const char *src);
char *get_file_extension(const char *path);
void set_nonblocking(int sock);
int parse_http_request(const char *buffer, size_t len, http_request_t *req);
void build_http_response(http_response_t *resp, char *buffer, size_t *len);

// Error handling
#define LOG_ERROR(fmt, ...) logger_error("%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) logger_debug("%s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

// Memory management
#define MALLOC_CHECK(ptr, ...)                                      \
    do                                                              \
    {                                                               \
        if ((ptr) == NULL)                                          \
        {                                                           \
            LOG_ERROR("Memory allocation failed: %s", __VA_ARGS__); \
            exit(EXIT_FAILURE);                                     \
        }                                                           \
    } while (0)

#endif // HTTPS_SERVER_H