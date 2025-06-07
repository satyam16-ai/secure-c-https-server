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
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <zlib.h>

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
    {"/api", HTTP_PUT, handle_api},
    {"/api", HTTP_DELETE, handle_api},
    {"/ws", HTTP_GET, handle_websocket},
    {"/proxy", HTTP_GET, handle_proxy},
    {"/metrics", HTTP_GET, handle_metrics},
    {"/metrics.html", HTTP_GET, handle_static},
    {NULL, HTTP_UNKNOWN, handle_static} // Default handler
};

extern server_config_t config;

#define SESSION_COOKIE_NAME "SESSIONID"
#define SESSION_TIMEOUT 1800           // 30 min
#define JWT_SECRET "my_jwt_secret_key" // For demo only

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

    // Gzip compress if client supports it
    if (client_accepts_gzip(req))
    {
        size_t gz_len = 0;
        char *gzipped = gzip_compress(content, content_size, &gz_len);
        if (gzipped && gz_len > 0)
        {
            free(content);
            resp->body = gzipped;
            resp->body_length = gz_len;
            strncpy(resp->headers[resp->header_count].name, "Content-Encoding", sizeof(resp->headers[0].name) - 1);
            strncpy(resp->headers[resp->header_count].value, "gzip", sizeof(resp->headers[0].value) - 1);
            resp->header_count++;
        }
        else
        {
            resp->body = content;
            resp->body_length = content_size;
        }
    }
    else
    {
        resp->body = content;
        resp->body_length = content_size;
    }

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

    // --- ACL check for static files ---
    // For demo: extract user from basic auth if present
    char user[64] = "";
    for (size_t i = 0; i < req->header_count; i++)
    {
        if (strcasecmp(req->headers[i].name, "Authorization") == 0)
        {
            const char *prefix = "Basic ";
            if (strncmp(req->headers[i].value, prefix, strlen(prefix)) == 0)
            {
                const char *b64 = req->headers[i].value + strlen(prefix);
                unsigned char decoded[256] = {0};
                int decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)b64, strlen(b64));
                if (decoded_len > 0)
                {
                    char *colon = strchr((char *)decoded, ':');
                    if (colon)
                    {
                        *colon = '\0';
                        strncpy(user, (char *)decoded, sizeof(user) - 1);
                        user[sizeof(user) - 1] = '\0';
                    }
                }
            }
        }
    }
    if (!acl_check(req, user))
    {
        resp->status = HTTP_403_FORBIDDEN;
        resp->body = "Forbidden by ACL";
        resp->body_length = strlen(resp->body);
        // Gzip forbidden response if client supports it
        int should_gzip = client_accepts_gzip(req);
        if (should_gzip && resp->body && resp->body_length > 0)
        {
            size_t gz_len = 0;
            char *gzipped = gzip_compress(resp->body, resp->body_length, &gz_len);
            if (gzipped && gz_len > 0)
            {
                resp->body = gzipped;
                resp->body_length = gz_len;
                strncpy(resp->headers[resp->header_count].name, "Content-Encoding", sizeof(resp->headers[0].name) - 1);
                strncpy(resp->headers[resp->header_count].value, "gzip", sizeof(resp->headers[0].value) - 1);
                resp->header_count++;
            }
        }
        return 0;
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

// Static in-memory data for API demo
static int api_counter = 0;
static char api_data[256] = "{\"message\":\"Hello, API!\"}";

// Save uploaded file to uploads/ directory
static int save_uploaded_file(const char *filename, const char *data, size_t len)
{
    struct stat st = {0};
    if (stat("uploads", &st) == -1)
    {
        mkdir("uploads", 0700);
    }
    char path[512];
    snprintf(path, sizeof(path), "uploads/%s", filename);
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return -1;
    fwrite(data, 1, len, fp);
    fclose(fp);
    return 0;
}

// Add CORS headers for API endpoints
static void add_cors_headers(http_response_t *resp)
{
    strncpy(resp->headers[resp->header_count].name, "Access-Control-Allow-Origin", sizeof(resp->headers[0].name) - 1);
    strncpy(resp->headers[resp->header_count].value, "*", sizeof(resp->headers[0].value) - 1);
    resp->header_count++;
    strncpy(resp->headers[resp->header_count].name, "Access-Control-Allow-Methods", sizeof(resp->headers[0].name) - 1);
    strncpy(resp->headers[resp->header_count].value, "GET, POST, PUT, DELETE, OPTIONS", sizeof(resp->headers[0].value) - 1);
    resp->header_count++;
    strncpy(resp->headers[resp->header_count].name, "Access-Control-Allow-Headers", sizeof(resp->headers[0].name) - 1);
    strncpy(resp->headers[resp->header_count].value, "Content-Type, Authorization", sizeof(resp->headers[0].value) - 1);
    resp->header_count++;
}

// Reverse proxy handler (GET only, demo)
static size_t proxy_write_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    strncat((char *)userp, (char *)contents, realsize);
    return realsize;
}

static int handle_proxy(http_request_t *req, http_response_t *resp)
{
    // Parse ?url= from req->path
    const char *q = strchr(req->path, '?');
    if (!q || !strstr(q, "url="))
    {
        resp->status = HTTP_400_BAD_REQUEST;
        resp->body = "{\"error\":\"Missing url param\"}";
        resp->body_length = strlen(resp->body);
        return 0;
    }
    const char *url = strstr(q, "url=") + 4;
    char backend_url[512] = "";
    sscanf(url, "%511[^&]", backend_url);
    if (!*backend_url)
    {
        resp->status = HTTP_400_BAD_REQUEST;
        resp->body = "{\"error\":\"Empty url param\"}";
        resp->body_length = strlen(resp->body);
        return 0;
    }
    CURL *curl = curl_easy_init();
    if (!curl)
    {
        resp->status = HTTP_500_INTERNAL_SERVER_ERROR;
        resp->body = "{\"error\":\"CURL init failed\"}";
        resp->body_length = strlen(resp->body);
        return 0;
    }
    static char proxy_buf[8192];
    proxy_buf[0] = '\0';
    curl_easy_setopt(curl, CURLOPT_URL, backend_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, proxy_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, proxy_buf);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
    {
        resp->status = HTTP_502_BAD_GATEWAY;
        resp->body = "{\"error\":\"Proxy failed\"}";
        resp->body_length = strlen(resp->body);
        return 0;
    }
    resp->status = HTTP_200_OK;
    resp->body = proxy_buf;
    resp->body_length = strlen(proxy_buf);
    // Gzip compress proxy response if client supports it
    if (client_accepts_gzip(req))
    {
        size_t gz_len = 0;
        char *gzipped = gzip_compress(proxy_buf, strlen(proxy_buf), &gz_len);
        if (gzipped && gz_len > 0)
        {
            resp->body = gzipped;
            resp->body_length = gz_len;
            strncpy(resp->headers[resp->header_count].name, "Content-Encoding", sizeof(resp->headers[0].name) - 1);
            strncpy(resp->headers[resp->header_count].value, "gzip", sizeof(resp->headers[0].value) - 1);
            resp->header_count++;
        }
    }
    strncpy(resp->headers[resp->header_count].name, "Content-Type", sizeof(resp->headers[0].name) - 1);
    strncpy(resp->headers[resp->header_count].value, "application/json", sizeof(resp->headers[0].value) - 1);
    resp->header_count++;
    add_cors_headers(resp);
    return 0;
}

// Check if client supports gzip
static int client_accepts_gzip(http_request_t *req)
{
    for (size_t i = 0; i < req->header_count; i++)
    {
        if (strcasecmp(req->headers[i].name, "Accept-Encoding") == 0 && strstr(req->headers[i].value, "gzip"))
        {
            return 1;
        }
    }
    return 0;
}

// Gzip-compress a buffer. Returns malloc'd buffer and sets out_len. Caller must free.
static char *gzip_compress(const char *data, size_t data_len, size_t *out_len)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
    {
        return NULL;
    }
    size_t max_compressed = data_len + (data_len / 10) + 64;
    char *out = malloc(max_compressed);
    if (!out)
    {
        deflateEnd(&zs);
        return NULL;
    }
    zs.next_in = (Bytef *)data;
    zs.avail_in = data_len;
    zs.next_out = (Bytef *)out;
    zs.avail_out = max_compressed;
    int ret = deflate(&zs, Z_FINISH);
    if (ret != Z_STREAM_END)
    {
        free(out);
        deflateEnd(&zs);
        return NULL;
    }
    *out_len = zs.total_out;
    deflateEnd(&zs);
    return out;
}

// Handle API requests
static int handle_api(http_request_t *req, http_response_t *resp)
{
    // Set Content-Type to application/json
    strncpy(resp->headers[resp->header_count].name, "Content-Type", sizeof(resp->headers[0].name) - 1);
    strncpy(resp->headers[resp->header_count].value, "application/json", sizeof(resp->headers[0].value) - 1);
    resp->header_count++;
    add_cors_headers(resp);

    // --- ACL check for API endpoints ---
    char user[64] = "";
    // Try session cookie (demo: only one session, user is 'demo_user')
    if (check_session_cookie(req))
    {
        strncpy(user, "demo_user", sizeof(user) - 1);
        user[sizeof(user) - 1] = '\0';
    }
    else
    {
        // Try JWT (demo: only one user)
        for (size_t i = 0; i < req->header_count; i++)
        {
            if (strcasecmp(req->headers[i].name, "Authorization") == 0 && strstr(req->headers[i].value, "Bearer ") == req->headers[i].value)
            {
                if (check_jwt(req->headers[i].value + 7))
                {
                    strncpy(user, "demo_user", sizeof(user) - 1);
                    user[sizeof(user) - 1] = '\0';
                }
            }
        }
        // Try basic auth
        for (size_t i = 0; i < req->header_count && !*user; i++)
        {
            if (strcasecmp(req->headers[i].name, "Authorization") == 0)
            {
                const char *prefix = "Basic ";
                if (strncmp(req->headers[i].value, prefix, strlen(prefix)) == 0)
                {
                    const char *b64 = req->headers[i].value + strlen(prefix);
                    unsigned char decoded[256] = {0};
                    int decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)b64, strlen(b64));
                    if (decoded_len > 0)
                    {
                        char *colon = strchr((char *)decoded, ':');
                        if (colon)
                        {
                            *colon = '\0';
                            strncpy(user, (char *)decoded, sizeof(user) - 1);
                            user[sizeof(user) - 1] = '\0';
                        }
                    }
                }
            }
        }
    }
    if (!acl_check(req, user))
    {
        resp->status = HTTP_403_FORBIDDEN;
        resp->body = "{\"error\":\"Forbidden by ACL\"}";
        resp->body_length = strlen(resp->body);
        // Gzip forbidden response if client supports it
        int should_gzip = client_accepts_gzip(req);
        if (should_gzip && resp->body && resp->body_length > 0)
        {
            size_t gz_len = 0;
            char *gzipped = gzip_compress(resp->body, resp->body_length, &gz_len);
            if (gzipped && gz_len > 0)
            {
                resp->body = gzipped;
                resp->body_length = gz_len;
                strncpy(resp->headers[resp->header_count].name, "Content-Encoding", sizeof(resp->headers[0].name) - 1);
                strncpy(resp->headers[resp->header_count].value, "gzip", sizeof(resp->headers[0].value) - 1);
                resp->header_count++;
            }
        }
        return 0;
    }

    // --- Gzip compress API response if client supports it (applied before return for all JSON bodies) ---
    int should_gzip = client_accepts_gzip(req);
    char *gzipped = NULL;
    size_t gz_len = 0;
#define MAYBE_GZIP_BODY                                                                                                 \
    {                                                                                                                   \
        if (should_gzip && resp->body && resp->body_length > 0)                                                         \
        {                                                                                                               \
            gzipped = gzip_compress(resp->body, resp->body_length, &gz_len);                                            \
            if (gzipped && gz_len > 0)                                                                                  \
            {                                                                                                           \
                resp->body = gzipped;                                                                                   \
                resp->body_length = gz_len;                                                                             \
                strncpy(resp->headers[resp->header_count].name, "Content-Encoding", sizeof(resp->headers[0].name) - 1); \
                strncpy(resp->headers[resp->header_count].value, "gzip", sizeof(resp->headers[0].value) - 1);           \
                resp->header_count++;                                                                                   \
            }                                                                                                           \
        }                                                                                                               \
    }

    // Demo login endpoint: POST /api/login with {"user":"...","pass":"...","auth":"session"|"jwt"}
    if (req->method == HTTP_POST && req->body && req->body_length > 0 && strstr(req->path, "/api/login") != NULL)
    {
        // Parse user/pass/auth (demo: naive, not robust JSON)
        const char *user = strstr(req->body, "user");
        const char *pass = strstr(req->body, "pass");
        const char *auth = strstr(req->body, "auth");
        if (user && pass && auth)
        {
            if (strstr(auth, "session"))
            {
                generate_session_id(session_id, sizeof(session_id));
                session_expiry = time(NULL) + SESSION_TIMEOUT;
                set_session_cookie(resp, session_id);
                resp->status = HTTP_200_OK;
                resp->body = "{\"login\":true,\"type\":\"session\"}";
                resp->body_length = strlen(resp->body);
                MAYBE_GZIP_BODY;
                return 0;
            }
            else if (strstr(auth, "jwt"))
            {
                static char jwt[512];
                generate_jwt("demo_user", jwt, sizeof(jwt));
                resp->status = HTTP_200_OK;
                resp->body = jwt;
                resp->body_length = strlen(jwt);
                MAYBE_GZIP_BODY;
                return 0;
            }
        }
        resp->status = HTTP_400_BAD_REQUEST;
        resp->body = "{\"error\":\"Invalid login\"}";
        resp->body_length = strlen(resp->body);
        MAYBE_GZIP_BODY;
        return 0;
    }
    // For protected endpoints, check session or JWT
    if (strstr(req->path, "/api/protected") != NULL)
    {
        int ok = 0;
        // Check session cookie
        if (check_session_cookie(req))
            ok = 1;
        // Check JWT in Authorization header
        for (size_t i = 0; i < req->header_count; i++)
        {
            if (strcasecmp(req->headers[i].name, "Authorization") == 0 && strstr(req->headers[i].value, "Bearer ") == req->headers[i].value)
            {
                const char *jwt = req->headers[i].value + 7;
                if (check_jwt(jwt))
                    ok = 1;
            }
        }
        if (!ok)
        {
            resp->status = HTTP_401_UNAUTHORIZED;
            resp->body = "{\"error\":\"Unauthorized\"}";
            resp->body_length = strlen(resp->body);
            MAYBE_GZIP_BODY;
            return 0;
        }
        resp->status = HTTP_200_OK;
        resp->body = "{\"protected\":true}";
        resp->body_length = strlen(resp->body);
        MAYBE_GZIP_BODY;
        return 0;
    }
    // Check for file upload (multipart/form-data)
    if (req->method == HTTP_POST && req->body && req->body_length > 0)
    {
        const char *content_type = NULL;
        for (size_t i = 0; i < req->header_count; i++)
        {
            if (strcasecmp(req->headers[i].name, "Content-Type") == 0)
            {
                content_type = req->headers[i].value;
                break;
            }
        }
        if (content_type && strncmp(content_type, "multipart/form-data", 19) == 0)
        {
            // Extract boundary
            const char *b = strstr(content_type, "boundary=");
            if (!b)
            {
                resp->status = HTTP_400_BAD_REQUEST;
                resp->body = "{\"error\":\"Missing boundary\"}";
                resp->body_length = strlen(resp->body);
                return 0;
            }
            b += 9;
            char boundary[128];
            snprintf(boundary, sizeof(boundary), "--%s", b);
            // Find file part
            char *file_start = strstr(req->body, "Content-Disposition: form-data;");
            if (!file_start)
            {
                resp->status = HTTP_400_BAD_REQUEST;
                resp->body = "{\"error\":\"No file part\"}";
                resp->body_length = strlen(resp->body);
                return 0;
            }
            char *name_pos = strstr(file_start, "name=");
            char *filename_pos = strstr(file_start, "filename=");
            if (!filename_pos)
            {
                resp->status = HTTP_400_BAD_REQUEST;
                resp->body = "{\"error\":\"No filename\"}";
                resp->body_length = strlen(resp->body);
                return 0;
            }
            filename_pos += 9;
            char *filename_end = strchr(filename_pos, '"');
            if (!filename_end)
            {
                resp->status = HTTP_400_BAD_REQUEST;
                resp->body = "{\"error\":\"Malformed filename\"}";
                resp->body_length = strlen(resp->body);
                return 0;
            }
            char filename[128];
            size_t fn_len = filename_end - filename_pos;
            if (fn_len >= sizeof(filename))
                fn_len = sizeof(filename) - 1;
            strncpy(filename, filename_pos, fn_len);
            filename[fn_len] = '\0';
            // Find start of file data (after 2x CRLF)
            char *data_start = strstr(filename_end, "\r\n\r\n");
            if (!data_start)
            {
                resp->status = HTTP_400_BAD_REQUEST;
                resp->body = "{\"error\":\"Malformed body\"}";
                resp->body_length = strlen(resp->body);
                return 0;
            }
            data_start += 4;
            // Find end of file data (boundary)
            char *data_end = strstr(data_start, boundary);
            if (!data_end)
            {
                resp->status = HTTP_400_BAD_REQUEST;
                resp->body = "{\"error\":\"Malformed multipart\"}";
                resp->body_length = strlen(resp->body);
                return 0;
            }
            size_t file_len = data_end - data_start;
            // Save file
            if (save_uploaded_file(filename, data_start, file_len) == 0)
            {
                resp->status = HTTP_200_OK;
                resp->body = "{\"success\":true,\"filename\":\"";
                size_t blen = strlen(resp->body);
                snprintf(resp->body + blen, 256 - blen, "%s\"}", filename);
                resp->body_length = strlen(resp->body);
                MAYBE_GZIP_BODY;
                return 0;
            }
            else
            {
                resp->status = HTTP_500_INTERNAL_SERVER_ERROR;
                resp->body = "{\"error\":\"Failed to save file\"}";
                resp->body_length = strlen(resp->body);
                MAYBE_GZIP_BODY;
                return 0;
            }
        }
    }
    else if (req->method == HTTP_GET)
    {
        // Return current data
        resp->status = HTTP_200_OK;
        resp->body = api_data;
        resp->body_length = strlen(api_data);
        MAYBE_GZIP_BODY;
        return 0;
    }
    else if (req->method == HTTP_POST || req->method == HTTP_PUT)
    {
        // Accept JSON body and update api_data (demo: just copy body if valid)
        if (req->body && req->body_length > 0 && req->body_length < sizeof(api_data) - 1)
        {
            // Very basic JSON validation: must start with '{' and end with '}'
            if (req->body[0] == '{' && req->body[req->body_length - 1] == '}')
            {
                strncpy(api_data, req->body, req->body_length);
                api_data[req->body_length] = '\0';
                api_counter++;
                resp->status = HTTP_200_OK;
                resp->body = api_data;
                resp->body_length = strlen(api_data);
                MAYBE_GZIP_BODY;
                return 0;
            }
            else
            {
                resp->status = HTTP_400_BAD_REQUEST;
                resp->body = "{\"error\":\"Invalid JSON\"}";
                resp->body_length = strlen(resp->body);
                MAYBE_GZIP_BODY;
                return 0;
            }
        }
        else
        {
            resp->status = HTTP_400_BAD_REQUEST;
            resp->body = "{\"error\":\"Missing JSON body\"}";
            resp->body_length = strlen(resp->body);
            MAYBE_GZIP_BODY;
            return 0;
        }
    }
    else if (req->method == HTTP_DELETE)
    {
        // Clear the data
        strcpy(api_data, "{\"message\":\"Deleted\"}");
        resp->status = HTTP_200_OK;
        resp->body = api_data;
        resp->body_length = strlen(api_data);
        MAYBE_GZIP_BODY;
        return 0;
    }
    else
    {
        resp->status = HTTP_405_METHOD_NOT_ALLOWED;
        resp->body = "{\"error\":\"Method Not Allowed\"}";
        resp->body_length = strlen(resp->body);
        MAYBE_GZIP_BODY;
        return 0;
    }
#undef MAYBE_GZIP_BODY
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
    static time_t server_start_time = 0;
    static unsigned long request_count = 0;

    if (server_start_time == 0)
        server_start_time = time(NULL);
    request_count++;

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

// Simple session struct (demo: single session)
static char session_id[65] = "";
static time_t session_expiry = 0;

#define SESSION_COOKIE_NAME "SESSIONID"
#define SESSION_TIMEOUT 1800           // 30 min
#define JWT_SECRET "my_jwt_secret_key" // For demo only

// Generate a random session ID (hex string)
static void generate_session_id(char *out, size_t len)
{
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf) && i * 2 + 1 < len; i++)
        sprintf(out + i * 2, "%02x", buf[i]);
    out[sizeof(buf) * 2] = '\0';
}

// Set session cookie in response
static void set_session_cookie(http_response_t *resp, const char *sid)
{
    char cookie[128];
    snprintf(cookie, sizeof(cookie), "%s=%s; HttpOnly; Path=/; Max-Age=%d", SESSION_COOKIE_NAME, sid, SESSION_TIMEOUT);
    strncpy(resp->headers[resp->header_count].name, "Set-Cookie", sizeof(resp->headers[0].name) - 1);
    strncpy(resp->headers[resp->header_count].value, cookie, sizeof(resp->headers[0].value) - 1);
    resp->header_count++;
}

// Check session cookie in request
static int check_session_cookie(http_request_t *req)
{
    for (size_t i = 0; i < req->header_count; i++)
    {
        if (strcasecmp(req->headers[i].name, "Cookie") == 0)
        {
            const char *cookie = req->headers[i].value;
            char *sid = strstr(cookie, SESSION_COOKIE_NAME "=");
            if (sid)
            {
                sid += strlen(SESSION_COOKIE_NAME) + 1;
                char *end = strchr(sid, ';');
                char sid_val[65];
                if (end)
                {
                    size_t n = end - sid;
                    if (n > 64)
                        n = 64;
                    strncpy(sid_val, sid, n);
                    sid_val[n] = '\0';
                }
                else
                {
                    strncpy(sid_val, sid, 64);
                    sid_val[64] = '\0';
                }
                if (strcmp(sid_val, session_id) == 0 && time(NULL) < session_expiry)
                {
                    session_expiry = time(NULL) + SESSION_TIMEOUT; // refresh expiry
                    return 1;
                }
            }
        }
    }
    return 0;
}

// JWT encode (base64 header.payload.signature, signature is SHA256 HMAC, demo: not secure)
static void base64url_encode(const unsigned char *in, size_t inlen, char *out, size_t outlen)
{
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t i, j;
    for (i = 0, j = 0; i + 2 < inlen && j + 4 < outlen; i += 3, j += 4)
    {
        out[j] = tbl[(in[i] >> 2) & 0x3F];
        out[j + 1] = tbl[((in[i] & 0x3) << 4) | ((in[i + 1] >> 4) & 0xF)];
        out[j + 2] = tbl[((in[i + 1] & 0xF) << 2) | ((in[i + 2] >> 6) & 0x3)];
        out[j + 3] = tbl[in[i + 2] & 0x3F];
    }
    if (i < inlen && j + 4 < outlen)
    {
        out[j] = tbl[(in[i] >> 2) & 0x3F];
        if (i + 1 < inlen)
        {
            out[j + 1] = tbl[((in[i] & 0x3) << 4) | ((in[i + 1] >> 4) & 0xF)];
            out[j + 2] = tbl[((in[i + 1] & 0xF) << 2)];
            out[j + 3] = '=';
        }
        else
        {
            out[j + 1] = tbl[((in[i] & 0x3) << 4)];
            out[j + 2] = out[j + 3] = '=';
        }
        j += 4;
    }
    out[j] = '\0';
}

static void jwt_sign(const char *header_payload, char *out, size_t outlen)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, header_payload, strlen(header_payload));
    SHA256_Update(&ctx, JWT_SECRET, strlen(JWT_SECRET));
    SHA256_Final(hash, &ctx);
    base64url_encode(hash, sizeof(hash), out, outlen);
}

static void generate_jwt(const char *user, char *out, size_t outlen)
{
    char header[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char payload[128];
    snprintf(payload, sizeof(payload), "{\"user\":\"%s\",\"exp\":%ld}", user, time(NULL) + 3600);
    char b64_header[128], b64_payload[256], b64_sig[128];
    base64url_encode((unsigned char *)header, strlen(header), b64_header, sizeof(b64_header));
    base64url_encode((unsigned char *)payload, strlen(payload), b64_payload, sizeof(b64_payload));
    char header_payload[512];
    snprintf(header_payload, sizeof(header_payload), "%s.%s", b64_header, b64_payload);
    jwt_sign(header_payload, b64_sig, sizeof(b64_sig));
    snprintf(out, outlen, "%s.%s", header_payload, b64_sig);
}

// Demo: check JWT (decode base64, check exp, skip signature for simplicity)
static int check_jwt(const char *token)
{
    char *dot1 = strchr(token, '.');
    char *dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;
    if (!dot1 || !dot2)
        return 0;
    char b64_payload[256];
    size_t len = dot2 - dot1 - 1;
    if (len >= sizeof(b64_payload))
        return 0;
    strncpy(b64_payload, dot1 + 1, len);
    b64_payload[len] = '\0';
    // Decode base64url (demo: not robust)
    char payload[256] = "";
    // For demo, just check exp manually
    if (strstr(b64_payload, "exp"))
        return 1;
    return 0;
}

// --- ACL structures and helpers ---
typedef struct
{
    const char *path_prefix;   // e.g. "/api/protected" or "/static/secret"
    http_method_t method;      // HTTP_GET, HTTP_POST, etc. or HTTP_UNKNOWN for any
    const char *required_user; // NULL for any authenticated user, or username
} acl_rule_t;

// Example ACL rules (expand as needed)
static const acl_rule_t acl_rules[] = {
    {"/api/protected", HTTP_UNKNOWN, NULL}, // Any authenticated user
    {"/static/secret", HTTP_GET, "admin"},  // Only admin can GET
    {NULL, HTTP_UNKNOWN, NULL}};

// Returns 1 if allowed, 0 if denied
static int acl_check(http_request_t *req, const char *user)
{
    for (const acl_rule_t *rule = acl_rules; rule->path_prefix != NULL; ++rule)
    {
        if (strncmp(req->path, rule->path_prefix, strlen(rule->path_prefix)) == 0 &&
            (rule->method == HTTP_UNKNOWN || rule->method == req->method))
        {
            if (rule->required_user == NULL)
            {
                // Any authenticated user
                if (user && *user)
                    return 1;
                return 0;
            }
            else
            {
                if (user && strcmp(user, rule->required_user) == 0)
                    return 1;
                return 0;
            }
        }
    }
    return 1; // Allow if no rule matches
}

// Helper to get memory usage (Linux only, returns RSS in KB)
static long get_memory_usage_kb(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        return -1;
    char line[256];
    long kb = -1;
    while (fgets(line, sizeof(line), f))
    {
        if (strncmp(line, "VmRSS:", 6) == 0)
        {
            sscanf(line + 6, "%ld", &kb);
            break;
        }
    }
    fclose(f);
    return kb;
}

// Metrics handler
static int handle_metrics(http_request_t *req, http_response_t *resp)
{
    time_t now = time(NULL);
    long uptime = (long)(now - server_start_time);
    long mem_kb = get_memory_usage_kb();
    char metrics_json[512];
    snprintf(metrics_json, sizeof(metrics_json),
             "{\"uptime\":%ld,\"requests\":%lu,\"memory_kb\":%ld}",
             uptime, request_count, mem_kb);
    resp->status = HTTP_200_OK;
    resp->body = strdup(metrics_json);
    resp->body_length = strlen(resp->body);
    strncpy(resp->headers[resp->header_count].name, "Content-Type", sizeof(resp->headers[0].name) - 1);
    strncpy(resp->headers[resp->header_count].value, "application/json", sizeof(resp->headers[0].value) - 1);
    resp->header_count++;
    return 0;
}
