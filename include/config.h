#ifndef CONFIG_H
#define CONFIG_H

#include "https_server.h"

int config_load(const char *filename, server_config_t *config);
void config_free(server_config_t *config);

#endif // CONFIG_H