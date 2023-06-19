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
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>  
#include <signal.h>
#include "typedefs.h"
#include "logger.h"



int             InitSocket(EndPoint_t clientType);
int             SendMessage(int fd, char *message, int messageSize, EndPoint_t loggingSource);
int             ReadMessage(int fd, char* buffer, int bufferSize, EndPoint_t loggingSource);
int             SendIdentity(int fd, EndPoint_t clientType);
void            HandleSignal(int signal, void (*handler)(int));