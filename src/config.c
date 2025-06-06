#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "config.h"

static char *trim_whitespace(char *str)
{
    char *end;
    while (isspace((unsigned char)*str))
        str++;
    if (*str == 0)
        return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;
    end[1] = '\0';
    return str;
}

int config_load(const char *filename, server_config_t *config)
{
    FILE *f = fopen(filename, "r");
    if (!f)
        return -1;
    char line[512];
    while (fgets(line, sizeof(line), f))
    {
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = trim_whitespace(line);
        char *val = trim_whitespace(eq + 1);
        if (strcmp(key, "port") == 0)
            config->port = atoi(val);
        else if (strcmp(key, "cert_file") == 0)
            config->cert_file = strdup(val);
        else if (strcmp(key, "key_file") == 0)
            config->key_file = strdup(val);
        else if (strcmp(key, "static_dir") == 0)
            config->static_dir = strdup(val);
        else if (strcmp(key, "log_dir") == 0)
            config->log_dir = strdup(val);
        else if (strcmp(key, "max_clients") == 0)
            config->max_clients = atoi(val);
        else if (strcmp(key, "backlog") == 0)
            config->backlog = atoi(val);
        else if (strcmp(key, "debug") == 0)
            config->debug = atoi(val);
        else if (strcmp(key, "auth_user") == 0)
            config->auth_user = strdup(val);
        else if (strcmp(key, "auth_pass") == 0)
            config->auth_pass = strdup(val);
    }
    fclose(f);
    return 0;
}

void config_free(server_config_t *config)
{
    if (config->cert_file)
        free(config->cert_file);
    if (config->key_file)
        free(config->key_file);
    if (config->static_dir)
        free(config->static_dir);
    if (config->log_dir)
        free(config->log_dir);
    if (config->auth_user)
        free(config->auth_user);
    if (config->auth_pass)
        free(config->auth_pass);
}