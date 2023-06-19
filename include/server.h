/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/


#pragma once
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <cjson/cJSON.h>
#include "typedefs.h"


int         InitSocketServ(fd_set *active_fd_set);
EndPoint_t  ClientIdentification(char *message);
int         ClientHandshake(fd_set *active_fd_set);
char*       PrepareJSONStructure(ClientAction_t type, struct evse_data *data, EndPoint_t client_type);
int         RequestData();
void        ProcessMessage(int i, char *message, struct evse_data *instance);
int         MainCycle(fd_set *active_fd_set, struct evse_data *data);
void        InitEVSE(struct evse_data* data);
int         isDenied(EndPoint_t client);
void        DenyClient(EndPoint_t client);
void        AllowClient(EndPoint_t client, char* clientString);
int         isConnected(EndPoint_t client);
int         GetEndpointIndex(EndPoint_t endpointType);
int         InitServerInstance();
int         ParseConfigFile();
int         ParseLoggingLevel(char* buffer);