#include "../include/https_server.h"
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sys/wait.h>
#include <stdio.h>
#include <syslog.h>
#include <strings.h>

// Route handler function type
typedef int (*route_handler_t)(http_request_t *req, http_response_t *resp);

// Route structure
typedef struct
{
    const char *path;
    http_method_t method;
    route_handler_t handler;
} route_t;

// Forward declarations of route handlers
static int handle_static(http_request_t *req, http_response_t *resp);
static int handle_status(http_request_t *req, http_response_t *resp);
static int handle_api(http_request_t *req, http_response_t *resp);
static int handle_websocket(http_request_t *req, http_response_t *resp);
static int handle_cgi(http_request_t *req, http_response_t *resp);

// Route table
static const route_t routes[] = {
    {"/status", HTTP_GET, handle_status},
    {"/api", HTTP_GET, handle_api},
    {"/api", HTTP_POST, handle_api},
    {"/ws", HTTP_GET, handle_websocket},
    {NULL, HTTP_UNKNOWN, handle_static} // Default handler
};

extern server_config_t config;

static int check_basic_auth(http_request_t *req)
{
    // Print all headers for debugging
    fprintf(stderr, "[DEBUG] Headers received (count=%zu):\n", req->header_count);
    for (size_t i = 0; i < req->header_count; i++)
    {
        fprintf(stderr, "[DEBUG]   %s: %s\n", req->headers[i].name, req->headers[i].value);
    }
    for (size_t i = 0; i < req->header_count; i++)
    {
        if (strcasecmp(req->headers[i].name, "Authorization") == 0)
        {
            fprintf(stderr, "[DEBUG] Authorization header value: %s\n", req->headers[i].value);
            const char *prefix = "Basic ";
            if (strncmp(req->headers[i].value, prefix, strlen(prefix)) == 0)
            {
                // Decode base64 using EVP_DecodeBlock
                const char *b64 = req->headers[i].value + strlen(prefix);
                size_t b64_len = strlen(b64);
                unsigned char decoded[256] = {0};
                int decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)b64, b64_len);
                if (decoded_len > 0)
                {
                    // Remove possible trailing newlines
                    while (decoded_len > 0 && (decoded[decoded_len - 1] == '\n' || decoded[decoded_len - 1] == '\r'))
                        decoded[--decoded_len] = '\0';
                    decoded[decoded_len] = '\0';
                    char *colon = strchr((char *)decoded, ':');
                    if (colon)
                    {
                        *colon = '\0';
                        const char *user = (char *)decoded;
                        const char *pass = colon + 1;
                        // Debug log
                        fprintf(stderr, "[DEBUG] Decoded user: '%s', pass: '%s'\n", user, pass);
                        if (config.auth_user && config.auth_pass &&
                            strcmp(user, config.auth_user) == 0 &&
                            strcmp(pass, config.auth_pass) == 0)
                        {
                            return 1; // Auth success
                        }
                    }
                }
            }
        }
    }
    return 0; // Auth failed
}

// Initialize router
int router_init(void)
{
    // Nothing to initialize for now
    return 0;
}

// Clean up router
void router_cleanup(void)
{
    // Nothing to clean up for now
}

// Find matching route
static const route_t *find_route(const char *path, http_method_t method)
{
    for (const route_t *route = routes; route->path != NULL; route++)
    {
        if (strcmp(route->path, path) == 0 &&
            (route->method == method || route->method == HTTP_UNKNOWN))
        {
            return route;
        }
    }
    return &routes[sizeof(routes) / sizeof(routes[0]) - 1]; // Default handler
}

// Handle static file request
static int handle_static(http_request_t *req, http_response_t *resp)
{
    char filepath[MAX_PATH_SIZE];
    struct stat st;
    char *content;
    size_t content_size;
    const char *mime_type;

    // Require Basic Auth for all static files
    if (!check_basic_auth(req))
    {
        resp->status = HTTP_401_UNAUTHORIZED;
        resp->body = "Unauthorized";
        resp->body_length = strlen(resp->body);
        strncpy(resp->headers[resp->header_count].name, "WWW-Authenticate", sizeof(resp->headers[0].name) - 1);
        strncpy(resp->headers[resp->header_count].value, "Basic realm=\"Secure Area\"", sizeof(resp->headers[0].value) - 1);
        resp->header_count++;
        return 0;
    }

    // Sanitize path to prevent directory traversal
    if (strstr(req->path, "..") != NULL || (req->path[0] == '/' && req->path[1] == '.'))
    {
        resp->status = HTTP_403_FORBIDDEN;
        resp->body = "Forbidden";
        resp->body_length = strlen(resp->body);
        return 0;
    }

    // Construct file path
    if (strcmp(req->path, "/") == 0)
    {
        strcpy(filepath, "static/index.html");
    }
    else
    {
        snprintf(filepath, sizeof(filepath), "static%.*s", (int)(sizeof(filepath) - 7 - 1), req->path);
    }

    // Check if file exists
    if (stat(filepath, &st) != 0)
    {
        resp->status = HTTP_404_NOT_FOUND;
        resp->body = "File not found";
        resp->body_length = strlen(resp->body);
        return 0;
    }

    // Check if it's a directory. If so, log (using syslog) that directory browsing (static) was called and then return a simple HTML listing.
    if (S_ISDIR(st.st_mode))
    {
        syslog(LOG_INFO, "Directory browsing (static) called");
        resp->status = HTTP_200_OK;
        resp->body = "<!DOCTYPE html><html><head><title>Directory Listing</title></head><body><h1>Directory Listing</h1><ul><li><a href=\"..\">..</a></li></ul></body></html>";
        resp->body_length = strlen(resp->body);
        strncpy(resp->headers[resp->header_count].name, "Content-Type", sizeof(resp->headers[0].name) - 1);
        strncpy(resp->headers[resp->header_count].value, "text/html", sizeof(resp->headers[0].value) - 1);
        resp->header_count++;
        return 0;
    }

    // Read file content
    content = read_file(filepath, &content_size);
    if (content == NULL)
    {
        resp->status = HTTP_500_INTERNAL_SERVER_ERROR;
        resp->body = "Failed to read file";
        resp->body_length = strlen(resp->body);
        return 0;
    }

    // Set response
    resp->status = HTTP_200_OK;
    resp->body = content;
    resp->body_length = content_size;

    // Set content type
    mime_type = mime_get_type(filepath);
    if (mime_type != NULL)
    {
        strncpy(resp->headers[resp->header_count].name, "Content-Type",
                sizeof(resp->headers[0].name) - 1);
        strncpy(resp->headers[resp->header_count].value, mime_type,
                sizeof(resp->headers[0].value) - 1);
        resp->header_count++;
    }

    return 0;
}

// Handle status request
static int handle_status(http_request_t *req, http_response_t *resp)
{
    (void)req; // Unused parameter

    // Log (using syslog) that the API status endpoint (/status) was called.
    syslog(LOG_INFO, "API status endpoint (/status) called");

    // Return a JSON payload (with a dummy uptime) for the /status endpoint.
    resp->status = HTTP_200_OK;
    resp->body = "{\"status\":\"running\",\"uptime\":0}";
    resp->body_length = strlen(resp->body);

    // Set the Content-Type header to application/json.
    strncpy(resp->headers[resp->header_count].name, "Content-Type", sizeof(resp->headers[0].name) - 1);
    strncpy(resp->headers[resp->header_count].value, "application/json", sizeof(resp->headers[0].value) - 1);
    resp->header_count++;

    return 0;
}

// Handle API requests
static int handle_api(http_request_t *req, http_response_t *resp)
{
    (void)req;
    // TODO: Implement API endpoints
    resp->status = HTTP_501_NOT_IMPLEMENTED;
    resp->body = "API not implemented";
    resp->body_length = strlen(resp->body);
    return 0;
}

// Handle WebSocket requests
static int handle_websocket(http_request_t *req, http_response_t *resp)
{
    (void)req;
    // Log (using syslog) that the WebSocket endpoint (/ws) was called (demo endpoint).
    syslog(LOG_INFO, "WebSocket endpoint (/ws) called");

    // For demo purposes, return a plain text message (even though a real WebSocket handshake isn't done).
    resp->status = HTTP_200_OK;
    resp->body = "WebSocket endpoint (demo) – a real WebSocket handshake isn't implemented.";
    resp->body_length = strlen(resp->body);
    strncpy(resp->headers[resp->header_count].name, "Content-Type", sizeof(resp->headers[0].name) - 1);
    strncpy(resp->headers[resp->header_count].value, "text/plain", sizeof(resp->headers[0].value) - 1);
    resp->header_count++;
    return 0;
}

// Handle CGI requests
static int handle_cgi(http_request_t *req, http_response_t *resp)
{
    char script_path[MAX_PATH_SIZE];
    if (strstr(req->path, "..") != NULL)
    {
        resp->status = HTTP_403_FORBIDDEN;
        resp->body = "Forbidden";
        resp->body_length = strlen(resp->body);
        return 0;
    }
    snprintf(script_path, sizeof(script_path), ".%s", req->path);
    struct stat st;
    if (stat(script_path, &st) != 0 || !(st.st_mode & S_IXUSR))
    {
        resp->status = HTTP_404_NOT_FOUND;
        resp->body = "CGI script not found or not executable";
        resp->body_length = strlen(resp->body);
        return 0;
    }
    int pipefd[2];
    if (pipe(pipefd) != 0)
    {
        resp->status = HTTP_500_INTERNAL_SERVER_ERROR;
        resp->body = "Failed to create pipe";
        resp->body_length = strlen(resp->body);
        return 0;
    }
    pid_t pid = fork();
    if (pid < 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        resp->status = HTTP_500_INTERNAL_SERVER_ERROR;
        resp->body = "Fork failed";
        resp->body_length = strlen(resp->body);
        return 0;
    }
    else if (pid == 0)
    {
        // Child: set up environment and exec
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        setenv("REQUEST_METHOD", req->method == HTTP_GET ? "GET" : req->method == HTTP_POST ? "POST"
                                                                                            : "OTHER",
               1);
        setenv("SCRIPT_NAME", script_path, 1);
        setenv("QUERY_STRING", "", 1); // TODO: parse query
        execl(script_path, script_path, NULL);
        exit(1);
    }
    else
    {
        // Parent: read output
        close(pipefd[1]);
        char cgi_output[8192];
        ssize_t n = read(pipefd[0], cgi_output, sizeof(cgi_output) - 1);
        close(pipefd[0]);
        int status = 0;
        waitpid(pid, &status, 0);
        if (n > 0)
        {
            cgi_output[n] = '\0';
            resp->status = HTTP_200_OK;
            resp->body = strdup(cgi_output);
            resp->body_length = strlen(resp->body);
        }
        else
        {
            resp->status = HTTP_500_INTERNAL_SERVER_ERROR;
            resp->body = "CGI script produced no output";
            resp->body_length = strlen(resp->body);
        }
        return 0;
    }
}

// Handle HTTP request
int router_handle_request(http_request_t *req, http_response_t *resp)
{
    const route_t *route;

    // Find matching route
    route = find_route(req->path, req->method);

    // Check for CGI requests
    if (strncmp(req->path, "/cgi-bin/", 9) == 0)
    {
        return handle_cgi(req, resp);
    }

    // Call route handler
    return route->handler(req, resp);
}
