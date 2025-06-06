#include "../include/https_server.h"
#include <sys/select.h>
#include <sys/time.h>

extern volatile int running;
volatile int running = 1;

static int server_socket = -1;
static client_t *clients[MAX_CLIENTS] = {NULL};
static thread_pool_t *thread_pool = NULL;

// Initialize server socket and bind to port
static int init_server_socket(int port, int backlog)
{
    struct sockaddr_in server_addr;
    int opt = 1;

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        LOG_ERROR("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    // Set socket options
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        LOG_ERROR("Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(server_socket);
        return -1;
    }

    // Set non-blocking mode
    set_nonblocking(server_socket);

    // Bind to port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        LOG_ERROR("Failed to bind to port %d: %s", port, strerror(errno));
        close(server_socket);
        return -1;
    }

    // Listen for connections
    if (listen(server_socket, backlog) < 0)
    {
        LOG_ERROR("Failed to listen: %s", strerror(errno));
        close(server_socket);
        return -1;
    }

    LOG_DEBUG("Server socket initialized on port %d", port);
    return 0;
}

// Find free client slot
static int find_free_client_slot(void)
{
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i] == NULL)
        {
            return i;
        }
    }
    return -1;
}

// Accept new client connection
static int accept_client(void)
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_socket;
    int slot;
    client_t *client;

    // Accept connection
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
    if (client_socket < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            LOG_ERROR("Failed to accept connection from %s: %s", inet_ntoa(client_addr.sin_addr), strerror(errno));
        }
        return -1;
    }

    // Find free client slot
    slot = find_free_client_slot();
    if (slot < 0)
    {
        LOG_ERROR("No free client slots available: %s", "dummy");
        close(client_socket);
        return -1;
    }

    // Create client structure
    client = (client_t *)malloc(sizeof(client_t));
    if (client == NULL)
    {
        LOG_ERROR("Failed to allocate client structure for %s: %s", inet_ntoa(client_addr.sin_addr), "dummy");
        close(client_socket);
        return -1;
    }

    // Initialize client
    memset(client, 0, sizeof(client_t));
    client->socket = client_socket;
    client->addr = client_addr;
    client->last_activity = time(NULL);
    client->keep_alive = 1;
    client->buffer_pos = 0;

    // Create SSL connection
    client->ssl = SSL_new(ssl_get_context());
    if (client->ssl == NULL)
    {
        LOG_ERROR("Failed to create SSL structure for %s: %s", inet_ntoa(client_addr.sin_addr), "dummy");
        free(client);
        close(client_socket);
        return -1;
    }

    if (SSL_set_fd(client->ssl, client_socket) != 1)
    {
        LOG_ERROR("Failed to set SSL file descriptor for %s: %s", inet_ntoa(client_addr.sin_addr), "dummy");
        SSL_free(client->ssl);
        free(client);
        close(client_socket);
        return -1;
    }

    // Accept SSL connection
    if (SSL_accept(client->ssl) != 1)
    {
        LOG_ERROR("SSL accept failed for %s (errno=%d): %s", inet_ntoa(client_addr.sin_addr), errno, strerror(errno));
        SSL_free(client->ssl);
        free(client);
        close(client_socket);
        return -1;
    }

    // Set non-blocking mode
    set_nonblocking(client_socket);

    // Add to clients array
    clients[slot] = client;

    LOG_DEBUG("New client connected from %s:%d",
              inet_ntoa(client_addr.sin_addr),
              ntohs(client_addr.sin_port));

    return slot;
}

// Handle client request
static void handle_client(client_t *client)
{
    http_request_t req;
    http_response_t resp;
    int bytes_read;
    char *buffer;
    size_t buffer_len;

    // Read request
    bytes_read = SSL_read(client->ssl, client->buffer + client->buffer_pos,
                          BUFFER_SIZE - client->buffer_pos);

    if (bytes_read <= 0)
    {
        int ssl_error = SSL_get_error(client->ssl, bytes_read);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
            return; // Try again later
        }
        LOG_DEBUG("Client disconnected or error: %s",
                  ERR_error_string(ssl_error, NULL));
        return;
    }

    client->buffer_pos += bytes_read;
    client->last_activity = time(NULL);

    // Parse request
    if (parse_http_request(client->buffer, client->buffer_pos, &req) != 0)
    {
        LOG_ERROR("Failed to parse HTTP request from %s: %s", inet_ntoa(client->addr.sin_addr), "dummy");
        return;
    }

    // Handle request
    memset(&resp, 0, sizeof(resp));
    resp.version = req.version;
    resp.keep_alive = req.version == HTTP_1_1;

    if (router_handle_request(&req, &resp) != 0)
    {
        resp.status = HTTP_500_INTERNAL_SERVER_ERROR;
        resp.body = "Internal Server Error";
        resp.body_length = strlen(resp.body);
    }

    // Build response
    buffer_len = MAX_HEADER_SIZE + resp.body_length;
    buffer = malloc(buffer_len);
    if (buffer == NULL)
    {
        LOG_ERROR("Failed to allocate response buffer for %s %s: %s", inet_ntoa(client->addr.sin_addr), req.path, "dummy");
        return;
    }

    build_http_response(&resp, buffer, &buffer_len);

    // Send response
    if (SSL_write(client->ssl, buffer, buffer_len) <= 0)
    {
        LOG_ERROR("Failed to send response to %s %s: %s", inet_ntoa(client->addr.sin_addr), req.path, ERR_error_string(SSL_get_error(client->ssl, -1), NULL));
    }

    // After sending response
    logger_access("%s - - \"%s %s HTTP/%s\" %d %zu", inet_ntoa(client->addr.sin_addr),
                  req.method == HTTP_GET ? "GET" : req.method == HTTP_POST ? "POST"
                                               : req.method == HTTP_HEAD   ? "HEAD"
                                                                           : "UNKNOWN",
                  req.path,
                  req.version == HTTP_1_0 ? "1.0" : req.version == HTTP_1_1 ? "1.1"
                                                                            : "?",
                  resp.status,
                  resp.body_length);

    free(buffer);

    // Clean up request
    if (req.body)
    {
        free(req.body);
    }

    // Reset buffer if not keep-alive
    if (!resp.keep_alive)
    {
        client->keep_alive = 0;
    }
    else
    {
        client->buffer_pos = 0;
    }
}

// Clean up client connection
static void cleanup_client(client_t *client)
{
    if (client->ssl)
    {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    close(client->socket);
    free(client);
}

// Main server loop
static int server_loop(void)
{
    fd_set read_fds;
    struct timeval tv;
    int max_fd;
    time_t now;

    while (running)
    {
        // Set up select timeout
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        // Set up file descriptor sets
        FD_ZERO(&read_fds);
        FD_SET(server_socket, &read_fds);
        max_fd = server_socket;

        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i] != NULL)
            {
                FD_SET(clients[i]->socket, &read_fds);
                if (clients[i]->socket > max_fd)
                {
                    max_fd = clients[i]->socket;
                }
            }
        }

        // Wait for activity
        if (select(max_fd + 1, &read_fds, NULL, NULL, &tv) < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            LOG_ERROR("Select failed: %s", strerror(errno));
            return -1;
        }

        // Check for new connections
        if (FD_ISSET(server_socket, &read_fds))
        {
            accept_client();
        }

        // Check existing clients
        now = time(NULL);
        for (int i = 0; i < MAX_CLIENTS; i++)
        {
            if (clients[i] == NULL)
            {
                continue;
            }

            // Check for timeout
            if (now - clients[i]->last_activity > 30)
            {
                LOG_DEBUG("Client timeout: %s", "dummy");
                cleanup_client(clients[i]);
                clients[i] = NULL;
                continue;
            }

            // Check for activity
            if (FD_ISSET(clients[i]->socket, &read_fds))
            {
                handle_client(clients[i]);

                // Clean up if not keep-alive
                if (!clients[i]->keep_alive)
                {
                    cleanup_client(clients[i]);
                    clients[i] = NULL;
                }
            }
        }
    }

    return 0;
}

// Initialize server
int server_init(server_config_t *config)
{
    // Initialize server socket
    if (init_server_socket(config->port, config->backlog) != 0)
    {
        return -1;
    }

    // Initialize thread pool
    thread_pool = thread_pool_create(4, 32); // 4 threads, queue size 32
    if (thread_pool == NULL)
    {
        LOG_ERROR("Failed to create thread pool: %s", "dummy");
        close(server_socket);
        return -1;
    }

    return 0;
}

// Run server
int server_run(server_config_t *config)
{
    (void)config; // Unused parameter
    return server_loop();
}

// Clean up server
void server_cleanup(void)
{
    // Clean up clients
    for (int i = 0; i < MAX_CLIENTS; i++)
    {
        if (clients[i] != NULL)
        {
            cleanup_client(clients[i]);
            clients[i] = NULL;
        }
    }

    // Clean up thread pool
    if (thread_pool != NULL)
    {
        thread_pool_destroy(thread_pool);
        thread_pool = NULL;
    }

    // Close server socket
    if (server_socket != -1)
    {
        close(server_socket);
        server_socket = -1;
    }
}
