/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/


#include "../include/comms.h"
#include "../include/utils.h"


// Log file descriptor
// default logging output is stdout
volatile int logFileDesc = STDOUT_FD;

// Logging level
LoggingLevel_t logLevel = ALL;

// Meter identity variable defined only in meter_app.c
EndPoint_t identity = METER;

// Meter local socket descriptor
int endpointFd;

int InitSerial(EndPoint_t clientType)
{
	//initialize serial port for reading
	struct termios term_set;
	char errorBuffer[ERRNO_MAX_SIZE];
	int term_port;
	int retCode;


	term_port = open(SERIAL_PORT, O_RDWR);
	if(term_port == -1)
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(clientType, FD_OPEN_FAIL, errorBuffer, logFileDesc);
		return term_port;
	}

	retCode = tcgetattr(term_port, &term_set);
	if(retCode == -1) {
		
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(clientType, SERIAL_INIT_FAIL, errorBuffer, logFileDesc);
		return retCode;
	}

	term_set.c_cflag &= ~PARENB;
	term_set.c_cflag &= ~CSTOPB;
	term_set.c_cflag &= ~CSIZE;
	term_set.c_cflag |= CS8;
	term_set.c_cflag &= ~CRTSCTS;
	term_set.c_cflag |= CREAD | CLOCAL;

	term_set.c_lflag |= ICANON;
	term_set.c_lflag &= ~ECHO;
	term_set.c_lflag &= ~ECHOE;
	term_set.c_lflag &= ~ECHONL;
	term_set.c_lflag &= ~ISIG;
	term_set.c_iflag &= ~(IXON | IXOFF | IXANY);
	term_set.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR);
	term_set.c_iflag |= ICRNL;

	term_set.c_oflag &= ~OPOST;
	term_set.c_oflag &= ~ONLCR;

	cfsetispeed(&term_set, B115200);
	cfsetospeed(&term_set, B115200);

	retCode = tcsetattr(term_port, TCSANOW, &term_set);
	if (retCode == -1) 
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(clientType, SERIAL_INIT_FAIL, errorBuffer, logFileDesc);
		return retCode;
	}
	else
	{
		LogEvent(clientType, SERIAL_INIT_OK, NULL, logFileDesc);
	}

	return term_port;
}



int ParseMeterMessage(char *message, struct meter_data *inst)
{
	char *pos, temp_message[16];
	int firstval = -1;
	
	pos = strtok(message, "]");
	while (pos != NULL)
	{
		switch (pos[strlen(pos)-1])
		{
		case '1':
			inst->current = atof(pos);
			break;
		case '2':
			inst->voltage = atof(pos);
			break;
		case '3':
			inst->power = atof(pos);
			break;
		case '4':
			strncpy(temp_message, pos,2);
			temp_message[0] += 16;
			strncpy(inst->chgsta,temp_message,1);
			inst->chgsta[1] = '\0';
			break;
		default:
			break;
		}

		if(firstval == -1) {
			firstval = pos[strlen(pos)-1]-'0';
		}
	
		pos = strtok(NULL, "]");
	}

	LogEvent(identity, PARSE_METER_DATA_OK, NULL, logFileDesc);

	if(firstval != 1){
		return 1;
	}

	return 0;
}


char* PrepareJSONMessage(struct meter_data inst, EndPoint_t clientType){
	char *buffer = NULL;
	cJSON *json_data = NULL;
	cJSON *json_meterdata = NULL;
	int res;

	json_data = cJSON_CreateObject();
	json_meterdata = cJSON_CreateObject();

	cJSON_AddNumberToObject(json_data, "Client", clientType);
	cJSON_AddItemToObject(json_data, "Data", json_meterdata);
	cJSON_AddStringToObject(json_meterdata, "chgsta", inst.chgsta);
	cJSON_AddNumberToObject(json_meterdata, "current", inst.current);
	cJSON_AddNumberToObject(json_meterdata, "power", inst.power);
	cJSON_AddNumberToObject(json_meterdata, "voltage", inst.voltage);

	buffer = cJSON_PrintUnformatted(json_data);
	cJSON_Delete(json_data);

	return buffer;
}


void UpdateCycle(int endpointFd, int uart_fd, EndPoint_t clientType)
{
	char messageBuffer[10000];
	char* messagePtr;
	int flags[] = {0, 0};
	struct meter_data local_inst = {0, 0, 0, 0};
	int retCode;

	while(1)
	{
		//clear messageBuffer before read
		memset(messageBuffer, 0, sizeof(messageBuffer));
		
		// read the message from server
		retCode = ReadMessage(endpointFd, messageBuffer, sizeof(messageBuffer), clientType);

		// if read failed, return from update_cyle
		if(retCode == -1)
		{
			return;
		}

		// check message type for client action status
		ParseJSONMessage(messageBuffer, flags, identity);

		// put meter in STATE A
		if(flags[PUSH_DATA]){
			SendMessage(uart_fd, "A\n", 2, clientType);
			flags[PUSH_DATA] = 0;
		}

		// ask meter for data
		retCode = SendMessage(uart_fd, "0\n", 2, clientType);
		if(retCode == -1)
		{
			return;
		}

		// read meter data response
		retCode = ReadMessage(uart_fd, messageBuffer, sizeof(messageBuffer), clientType);
		if(retCode == -1)
		{
			return;
		}

		// parse meter data response and load local_inst data structure
		while(ParseMeterMessage(messageBuffer, &local_inst) == 1){
			
			// read additional messages from uart connection
			retCode = ReadMessage(uart_fd, messageBuffer, sizeof(messageBuffer), clientType);
			if(retCode == -1)
			{
				return;
			}
		}

		// if server asked for meter's data encode local_inst as JSON string and send to server
		if(flags[GET_DATA])
		{
			messagePtr = PrepareJSONMessage(local_inst, clientType);
			retCode = SendMessage(endpointFd, messagePtr, strlen(messagePtr), clientType);
			
			if(retCode == -1)
			{
				return;
			}

			free(messagePtr);
			flags[GET_DATA] = 0;
			LogEvent(clientType, SEND_JSON_DATA_OK, NULL, logFileDesc);
		}
	}

}

int main(int argc, char* argv[]) 
{
	int uartfd, retCode;

	// setup signal handling
	HandleSignal(SIGUSR1,&CleanUp);

	// prepare the logging file structure based on evse.conf file parsed by server
	if(argc == 2)
	{
		logLevel = atoi(argv[1]);
		if(logLevel > NONE)
		{
			PrepareLoggingEnv(identity);
		}
	}

	// initialize serial communication channel
	uartfd = InitSerial(identity);
	if(uartfd == -1)
	{
		CleanUp(RUNTIME_ISSUE);
		return uartfd;
	}

	// initialize local socket communication
	endpointFd = InitSocket(identity);
	if(endpointFd == -1)
	{
		CleanUp(RUNTIME_ISSUE);
		return endpointFd;
	}
	
	// start client handshake procedure
	retCode = SendIdentity(endpointFd, identity);
	if(retCode == -1)
	{
		CleanUp(RUNTIME_ISSUE);
		return retCode;
	}

	// infinite processing loop
	UpdateCycle(endpointFd, uartfd, identity);
	
	// do the cleanup before exit
	CleanUp(RUNTIME_ISSUE);

	return 0;
}
