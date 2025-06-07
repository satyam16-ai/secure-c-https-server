#include "../include/https_server.h"
#include "../include/config.h"
#include <getopt.h>
#include <signal.h>

server_config_t config = {
    .port = DEFAULT_PORT,
    .cert_file = "certs/cert.pem",
    .key_file = "certs/key.pem",
    .static_dir = "static",
    .log_dir = "logs",
    .max_clients = MAX_CLIENTS,
    .backlog = DEFAULT_BACKLOG,
    .debug = 0};

static volatile int running = 1;

void signal_handler(int signum)
{
    (void)signum;
    running = 0;
}

void print_usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s [options]\n\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --port PORT       Specify server port (default: %d)\n", DEFAULT_PORT);
    fprintf(stderr, "  -d, --dir DIR         Set static files directory (default: %s)\n", config.static_dir);
    fprintf(stderr, "  -l, --log LOG_DIR     Set log directory (default: %s)\n", config.log_dir);
    fprintf(stderr, "  -c, --cert CERT_FILE  SSL certificate file (default: %s)\n", config.cert_file);
    fprintf(stderr, "  -k, --key KEY_FILE    SSL private key file (default: %s)\n", config.key_file);
    fprintf(stderr, "  -D, --debug           Enable debug mode\n");
    fprintf(stderr, "  -h, --help            Show this help message\n");
}

int parse_arguments(int argc, char *argv[])
{
    int opt;
    static struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"dir", required_argument, 0, 'd'},
        {"log", required_argument, 0, 'l'},
        {"cert", required_argument, 0, 'c'},
        {"key", required_argument, 0, 'k'},
        {"debug", no_argument, 0, 'D'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "p:d:l:c:k:Dh", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'p':
            config.port = atoi(optarg);
            if (config.port <= 0 || config.port > 65535)
            {
                fprintf(stderr, "Invalid port number: %s\n", optarg);
                return -1;
            }
            break;
        case 'd':
            config.static_dir = strdup(optarg);
            MALLOC_CHECK(config.static_dir, "dummy");
            break;
        case 'l':
            config.log_dir = strdup(optarg);
            MALLOC_CHECK(config.log_dir, "dummy");
            break;
        case 'c':
            config.cert_file = strdup(optarg);
            MALLOC_CHECK(config.cert_file, "dummy");
            break;
        case 'k':
            config.key_file = strdup(optarg);
            MALLOC_CHECK(config.key_file, "dummy");
            break;
        case 'D':
            config.debug = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 1;
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int ret;

    // Parse command line arguments
    ret = parse_arguments(argc, argv);
    if (ret != 0)
    {
        return ret == 1 ? 0 : 1;
    }

    // Load configuration from server.conf
    if (config_load("server.conf", &config) != 0)
    {
        fprintf(stderr, "Failed to load server.conf\n");
        return 1;
    }
    // Debug print loaded credentials
    printf("Loaded user: '%s', pass: '%s'\n", config.auth_user, config.auth_pass);

    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize logging
    logger_init(config.log_dir);
    LOG_DEBUG("Server starting with configuration: %s", "dummy");
    LOG_DEBUG("  Port: %d", config.port);
    LOG_DEBUG("  Static directory: %s", config.static_dir);
    LOG_DEBUG("  Log directory: %s", config.log_dir);
    LOG_DEBUG("  Certificate: %s", config.cert_file);
    LOG_DEBUG("  Private key: %s", config.key_file);
    LOG_DEBUG("  Debug mode: %s", config.debug ? "enabled" : "disabled");

    // Initialize SSL
    if (ssl_init(&config) != 0)
    {
        LOG_ERROR("Failed to initialize SSL: %s", "dummy");
        return 1;
    }

    // Initialize router
    if (router_init() != 0)
    {
        LOG_ERROR("Failed to initialize router: %s", "dummy");
        ssl_cleanup();
        return 1;
    }

    // Initialize MIME types
    mime_init();

    // Initialize server
    if (server_init(&config) != 0)
    {
        LOG_ERROR("Failed to initialize server: %s", "dummy");
        router_cleanup();
        ssl_cleanup();
        return 1;
    }

    // Run server
    LOG_DEBUG("Server initialized, starting main loop: %s", "dummy");
    ret = server_run(&config);

    // Cleanup
    LOG_DEBUG("Server shutting down, cleaning up: %s", "dummy");
    server_cleanup();
    router_cleanup();
    ssl_cleanup();
    logger_cleanup();

    // Free allocated memory
    if (strcmp(config.static_dir, "static") != 0)
        free(config.static_dir);
    if (strcmp(config.log_dir, "logs") != 0)
        free(config.log_dir);
    if (strcmp(config.cert_file, "certs/cert.pem") != 0)
        free(config.cert_file);
    if (strcmp(config.key_file, "certs/key.pem") != 0)
        free(config.key_file);

    return ret;
}
