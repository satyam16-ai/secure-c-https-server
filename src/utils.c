#include "../include/https_server.h"
#include <fcntl.h>
#include <ctype.h>

char *read_file(const char *path, size_t *size)
{
    FILE *fp = fopen(path, "rb");
    char *buf;
    size_t len;
    if (!fp)
        return NULL;
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buf = malloc(len + 1);
    if (!buf)
    {
        fclose(fp);
        return NULL;
    }
    fread(buf, 1, len, fp);
    buf[len] = '\0';
    fclose(fp);
    if (size)
        *size = len;
    return buf;
}

int is_directory(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        return 1;
    return 0;
}

char *url_decode(const char *src)
{
    char *dst = malloc(strlen(src) + 1);
    char a, b;
    size_t i, j = 0;
    for (i = 0; src[i]; i++)
    {
        if ((src[i] == '%') && ((a = src[i + 1]) && (b = src[i + 2])) && isxdigit(a) && isxdigit(b))
        {
            dst[j++] = (char)((isdigit(a) ? a - '0' : tolower(a) - 'a' + 10) << 4 |
                              (isdigit(b) ? b - '0' : tolower(b) - 'a' + 10));
            i += 2;
        }
        else if (src[i] == '+')
        {
            dst[j++] = ' ';
        }
        else
        {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
    return dst;
}

char *get_file_extension(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot || dot == path)
        return NULL;
    return (char *)dot;
}

void set_nonblocking(int sock)
{
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1)
        return;
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

// Basic HTTP request parser (GET/POST/HEAD, path, version)
int parse_http_request(const char *buffer, size_t len, http_request_t *req)
{
    char method[MAX_METHOD_SIZE], path[MAX_PATH_SIZE], version[MAX_VERSION_SIZE];
    size_t i = 0;
    req->header_count = 0;
    req->body = NULL;
    req->body_length = 0;

    // Parse request line
    if (sscanf(buffer, "%15s %1023s %15s\r\n", method, path, version) != 3)
        return -1;
    if (strcmp(method, "GET") == 0)
        req->method = HTTP_GET;
    else if (strcmp(method, "POST") == 0)
        req->method = HTTP_POST;
    else if (strcmp(method, "PUT") == 0)
        req->method = HTTP_PUT;
    else if (strcmp(method, "DELETE") == 0)
        req->method = HTTP_DELETE;
    else if (strcmp(method, "HEAD") == 0)
        req->method = HTTP_HEAD;
    else
        req->method = HTTP_UNKNOWN;
    strncpy(req->path, path, MAX_PATH_SIZE - 1);
    req->path[MAX_PATH_SIZE - 1] = '\0';
    if (strcmp(version, "HTTP/1.0") == 0)
        req->version = HTTP_1_0;
    else if (strcmp(version, "HTTP/1.1") == 0)
        req->version = HTTP_1_1;
    else
        req->version = HTTP_UNKNOWN_VERSION;

    // Move pointer past request line
    const char *p = strstr(buffer, "\r\n");
    if (!p)
        return -1;
    p += 2;

    // Parse headers
    while (*p && !(p[0] == '\r' && p[1] == '\n') && req->header_count < MAX_HEADER_COUNT)
    {
        const char *colon = strchr(p, ':');
        const char *line_end = strstr(p, "\r\n");
        if (!colon || !line_end || colon > line_end)
            break;
        size_t name_len = colon - p;
        size_t value_len = line_end - (colon + 1);
        while (value_len > 0 && (*(colon + 1 + value_len - 1) == ' ' || *(colon + 1 + value_len - 1) == '\t'))
            value_len--;
        while (name_len > 0 && (p[name_len - 1] == ' ' || p[name_len - 1] == '\t'))
            name_len--;
        size_t copy_name = name_len < sizeof(req->headers[0].name) - 1 ? name_len : sizeof(req->headers[0].name) - 1;
        size_t copy_value = value_len < sizeof(req->headers[0].value) - 1 ? value_len : sizeof(req->headers[0].value) - 1;
        strncpy(req->headers[req->header_count].name, p, copy_name);
        req->headers[req->header_count].name[copy_name] = '\0';
        while (*(colon + 1) == ' ' || *(colon + 1) == '\t')
            colon++;
        strncpy(req->headers[req->header_count].value, colon + 1, copy_value);
        req->headers[req->header_count].value[copy_value] = '\0';
        req->header_count++;
        p = line_end + 2;
    }

    // Move past header section
    if (p[0] == '\r' && p[1] == '\n')
        p += 2;

    // Parse body (for POST)
    if (req->method == HTTP_POST && *p)
    {
        req->body_length = len - (p - buffer);
        req->body = malloc(req->body_length + 1);
        if (req->body)
        {
            memcpy(req->body, p, req->body_length);
            req->body[req->body_length] = '\0';
        }
    }
    return 0;
}

// Basic HTTP response builder
void build_http_response(http_response_t *resp, char *buffer, size_t *len)
{
    int n = 0;
    const char *status_text;
    switch (resp->status)
    {
    case HTTP_200_OK:
        status_text = "OK";
        break;
    case HTTP_404_NOT_FOUND:
        status_text = "Not Found";
        break;
    case HTTP_403_FORBIDDEN:
        status_text = "Forbidden";
        break;
    case HTTP_500_INTERNAL_SERVER_ERROR:
        status_text = "Internal Server Error";
        break;
    case HTTP_501_NOT_IMPLEMENTED:
        status_text = "Not Implemented";
        break;
    default:
        status_text = "Error";
        break;
    }
    n += snprintf(buffer + n, *len - n, "HTTP/1.1 %d %s\r\n", resp->status, status_text);
    for (size_t i = 0; i < resp->header_count; i++)
    {
        n += snprintf(buffer + n, *len - n, "%s: %s\r\n", resp->headers[i].name, resp->headers[i].value);
    }
    n += snprintf(buffer + n, *len - n, "Content-Length: %zu\r\n", resp->body_length);
    if (resp->keep_alive)
        n += snprintf(buffer + n, *len - n, "Connection: keep-alive\r\n");
    else
        n += snprintf(buffer + n, *len - n, "Connection: close\r\n");
    n += snprintf(buffer + n, *len - n, "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n");
    n += snprintf(buffer + n, *len - n, "X-Content-Type-Options: nosniff\r\n");
    n += snprintf(buffer + n, *len - n, "X-Frame-Options: DENY\r\n");
    n += snprintf(buffer + n, *len - n, "X-XSS-Protection: 1; mode=block\r\n");
    n += snprintf(buffer + n, *len - n, "Referrer-Policy: no-referrer\r\n");
    n += snprintf(buffer + n, *len - n, "Content-Security-Policy: default-src 'self'\r\n");
    n += snprintf(buffer + n, *len - n, "\r\n");
    if (resp->body && resp->body_length > 0)
        memcpy(buffer + n, resp->body, resp->body_length);
    *len = n + resp->body_length;
}
