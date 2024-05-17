/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/

#ifndef UTILS_H
#define UTILS_H

#include <errno.h> 
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>  
#include <time.h>
#include "typedefs.h"
#include "logger.h"

#include <cjson/cJSON.h>

#define SERVER_CONF_FILE "evse.conf"
#define UART_BRIDGE_CONF_FILE "uart_bridge.conf"
#define CLOUD_CONF_FILE "cloud.conf"
#define MAX_LINE_LENGTH 1024
#define MAX_FILENAME_LENGTH 1024

void    GetTime(struct tm* dateTime);
int     LoadVariable(const char* fileName, const char* variableName, char* variableValue, size_t valueSize);
int     UpdateConfigFile(const char* fileName, const char* variableName, const char* newValue, const char* newVariable);
int     ConvertEndpointEnumToString(EndPoint_t clientType, char* clientName);

#endif // UTILS_H
