/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/


#pragma once
#include <errno.h> 
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>  
#include <time.h>
#include "typedefs.h"
#include "logger.h"

#include <cjson/cJSON.h>

// Cloud configs

#define CLOUD_MESSAGE_BUFFER_SIZE   10000

#define CLOUD_CONF_FILE "cloud.conf"
#define MAX_LINE_LENGTH 1024


void            GetTime(struct tm* dateTime);
int             ConvertEndpointStringToEnum(char* clientString, EndPoint_t loggingSource);
int             ConvertEndpointEnumToString(EndPoint_t clientType, char* clientName);
void            ParseJSONMessage(char *message, int *flags, EndPoint_t loggingSource);
void            CleanUp(int signal);
int             LoadVariable(const char* variableName, char* variableValue, size_t valueSize);
int             UpdateConfigFile(const char* variableName, const char* newValue, const char* newVariable);