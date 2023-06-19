/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/


#include "../include/comms.h"

// log file descriptor defined by each client
extern int logFileDesc;

int InitSocket(EndPoint_t loggingSource){

	struct sockaddr_un addr;
	char errorBuffer[ERRNO_MAX_SIZE];

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd  == -1) 
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
        LogEvent(loggingSource, SOCKET_CREATION_FAIL, errorBuffer, logFileDesc);
		return fd;
	}
	else
	{
		LogEvent(loggingSource, SOCKET_CREATION_OK, NULL, logFileDesc);
	}

	// initialize and configure sockaddr_un data structure
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "server.socket");

	// connect client socket with server socket
	int retCode = connect(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (retCode == -1) 
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(loggingSource, SOCKET_CONNECTION_FAIL, errorBuffer, logFileDesc);
        return retCode;
	}
	else
	{
		LogEvent(loggingSource, SOCKET_CONNECTION_OK, NULL, logFileDesc);
	}
	
	return fd;
}


int ReadMessage(int fd, char* buffer, int bufferSize, EndPoint_t loggingSource)
{
	char errorBuffer[ERRNO_MAX_SIZE];
	
	int readBytes = read(fd, buffer, bufferSize);
	if (readBytes == -1) 
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(loggingSource, READ_FAIL, errorBuffer, logFileDesc);
		return readBytes;
	}
	else
	{
		LogEvent(loggingSource, READ_OK, NULL, logFileDesc);
	}

	return readBytes;
}


int SendMessage(int fd, char *message, int messageSize, EndPoint_t loggingSource)
{
	int sentBytes;
	char errorBuffer[ERRNO_MAX_SIZE];

	sentBytes = write(fd, message, messageSize);
	if (sentBytes == -1) 
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(loggingSource, SEND_MESSAGE_FAIL, errorBuffer, logFileDesc);
		return sentBytes;
	}
	else
	{
		LogEvent(loggingSource, SEND_MESSAGE_OK, NULL, logFileDesc);
	}
	return sentBytes;
}


int SendIdentity(int fd, EndPoint_t loggingSource)
{
	char buffer[16];

	// convert loggingSource from integer format to char array format
	sprintf(buffer, "%d", loggingSource);

	int retCode = SendMessage(fd, buffer, strlen(buffer), loggingSource);
	if(retCode == -1)
	{
		LogEvent(loggingSource, SEND_IDENTITY_FAIL, NULL, logFileDesc);
		return retCode;
	}
	else
	{
		LogEvent(loggingSource, SEND_IDENTITY_OK, NULL, logFileDesc);
	}
	
	return 1;
}

void HandleSignal(int signal, void (*handler)(int))
{
	struct sigaction act;
	sigset_t mask;

	// block all signals, except the one used for cleanup
	sigfillset(&mask);
	sigdelset(&mask,signal);
	sigprocmask(SIG_SETMASK, &mask, NULL);

	// set the handler for the signal used to kill the process
	bzero(&act, sizeof(act));
	act.sa_handler = handler;	
	sigaction(signal, &act, NULL);
}
