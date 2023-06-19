/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/


#include "../include/server.h"
#include "../include/comms.h"


// Default logging file descriptor at startup
volatile int logFileDesc = STDOUT_FD;

// Default logging level at startup
LoggingLevel_t logLevel = ALL;

// Registered clients number
static int registeredClientsNo;

// Server instance structure
static struct fd_assoc instance;

// Server local socket descriptor 
int endpointFd;

// Server's identity
EndPoint_t identity = SERVER;

int InitSocketServ(fd_set *active_fd_set)
{
	struct sockaddr_un addr;
	char errorBuffer[ERRNO_MAX_SIZE];
	int fd;
	int retCode;

	// create and initialize server socket
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) 
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
			(__LINE__), __func__, errno, strerror(errno));
		LogEvent(identity, SOCKET_CREATION_FAIL, errorBuffer, logFileDesc);
		return fd;
	}
	else
	{
		LogEvent(identity, SOCKET_CREATION_OK, NULL, logFileDesc);
	}

	
	// initialize and configure socket address
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "server.socket");

	// create socket - address binding
	retCode = bind(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
	if (retCode == -1) 
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(identity, SOCKET_BIND_FAIL, errorBuffer, logFileDesc);
		return retCode;
	}	
	else
	{
		LogEvent(identity, SOCKET_BIND_OK, NULL, logFileDesc);
	}

	// put socket in listen mode
	retCode = listen(fd, registeredClientsNo);
	if (retCode == -1) 
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(identity, SOCKET_LISTEN_FAIL, errorBuffer, logFileDesc);
		return retCode;
	}
	else
	{
		LogEvent(identity, SOCKET_LISTEN_OK, NULL, logFileDesc);
	}	


	FD_ZERO(active_fd_set);
	FD_SET(fd, active_fd_set);

	return fd;
}

EndPoint_t ClientIdentification(char *message)
{
	EndPoint_t clientType = atoi(message);
	char errorBuffer[ERRNO_MAX_SIZE];
	
	switch (clientType)
	{
	case METER:
		return METER;
	case NFC:
		return NFC;
	case GUI:
		return GUI;
	case CLOUD:
		return CLOUD;
	default:
		sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
		LogEvent(identity, CLIENT_CONVERT_FAIL, errorBuffer, logFileDesc);
		return UNKNOWN_ENDPOINT;
	}
}

int ClientHandshake(fd_set *active_fd_set)
{
	fd_set read_fd_set;
	int retCode, i;
	int client_fd;
	char readBuffer[10];
	char errorBuffer[ERRNO_MAX_SIZE];
	int readBytes = 0;
	EndPoint_t clientType;
	int connectedEndpoints = 0;

	while(connectedEndpoints < instance.clients_arr_size)
	{
		read_fd_set = *active_fd_set;

		// check for ready connections
		retCode = select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
		if (retCode == -1) 
		{
			sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
					(__LINE__), __func__, errno, strerror(errno));
			LogEvent(identity, FD_SELECT_FAIL, errorBuffer, logFileDesc);
			return retCode;
		}

		// if select succeeded enroll clients to server
		if (retCode > 0)
		{
			for(i = 0; i < FD_SETSIZE; i++) {
				if(FD_ISSET(i, &read_fd_set)) 
				{
					// new connection to server
					if(i == instance.server_fd)
					{
						client_fd = accept(instance.server_fd, NULL, NULL);
						if (client_fd == -1) 
						{
							sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
									(__LINE__), __func__, errno, strerror(errno));
							LogEvent(identity, SOCKET_ACCEPT_FAIL, errorBuffer, logFileDesc);
							return client_fd;
						}
						else
						{
							LogEvent(identity, SOCKET_ACCEPT_OK, NULL, logFileDesc);
						}	

						FD_SET(client_fd, active_fd_set);		
					}
					// handshake data ready to be read on client <--> server connection
					else 
					{
						// Read client handshake message and determine its type
						readBytes = ReadMessage(i, readBuffer, sizeof(readBuffer), identity);
						if(readBytes == -1)
						{
							sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
										(__LINE__), __func__, errno, strerror(errno));
							LogEvent(identity,CLIENT_HANDSHAKE_FAIL,errorBuffer,logFileDesc);
							return readBytes;
						}
						clientType = ClientIdentification(readBuffer);
						
						// Check if the connected client is a known one, not already connected and not denied
						// then save its fd in the instance structure and mark it as CONNECTED
						if (clientType != UNKNOWN_ENDPOINT && 
							isDenied(clientType) == 0 &&
							isConnected(clientType) == 0)
						{
							int endpointIndex = GetEndpointIndex(clientType);
							if(endpointIndex == -1)
							{
								return endpointIndex;
							}

							instance.clients_arr[endpointIndex].fd = i;
							instance.clients_arr[endpointIndex].isConnected = true;
							connectedEndpoints++;
						}
						else
						{
							sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
										(__LINE__), __func__, errno, strerror(errno));
							LogEvent(identity,CLIENT_HANDSHAKE_FAIL,errorBuffer,logFileDesc);
							return -1;
						}
					}
				}
			}
		}	
		sleep(2);
	}
	LogEvent(identity, CLIENTS_HANDSHAKE_OK, NULL, logFileDesc);
	return 1;
}

char *PrepareJSONStructure(ClientAction_t type, struct evse_data *data, EndPoint_t client_type){
	char *buffer = NULL;
	char *temp = NULL;
	char errorBuffer[ERRNO_MAX_SIZE];
	cJSON *json_message = NULL;
	cJSON *json_data = NULL;
	cJSON *json_location = NULL;
	int retCode;

	json_message = cJSON_CreateObject();
	json_data = cJSON_CreateObject();
	json_location = cJSON_CreateObject();

	cJSON_AddNumberToObject(json_message, "Type", type);

	if(type == PUSH_DATA)
	{
		cJSON_AddItemToObject(json_message, "Data", json_data);

		//common data
		if(strlen(data->cmn.evse_id))
		{
			cJSON_AddStringToObject(json_data, "evse_id", data->cmn.evse_id);
		}
		else
		{
			cJSON_AddStringToObject(json_data, "evse_id", "N/A");
		}		
		cJSON_AddNumberToObject(json_data, "chg_cost", data->cmn.charge_cost);
		cJSON_AddNumberToObject(json_data, "evse_rating", data->cmn.evse_rating);
		cJSON_AddNumberToObject(json_data, "temperature", data->cmn.temperature);
		cJSON_AddStringToObject(json_data, "vehicle_auth", data->cmn.vehicle_auth);		
		cJSON_AddStringToObject(json_data, "chg_time", data->cmn.chg_time);						

		//meter data

		cJSON_AddStringToObject(json_data, "chgsta", data->met.chgsta);
		cJSON_AddNumberToObject(json_data, "current", data->met.current);
		cJSON_AddNumberToObject(json_data, "power", data->met.power);
		cJSON_AddNumberToObject(json_data, "voltage", data->met.voltage);

		//nfc data
		if(strlen(data->nfc.id)){
			cJSON_AddStringToObject(json_data, "card_id", data->nfc.id);
		}
		else{
			cJSON_AddStringToObject(json_data, "card_id", "N/A");
		}
		//gui data
		cJSON_AddNumberToObject(json_data, "battery_value", data->gui.battery);

		//cloud data
		cJSON_AddNumberToObject(json_data, "grid_pwr_lim", data->cloud.grid_pwr_lim);


		if(client_type == CLOUD){
			//common data
			cJSON_AddNumberToObject(json_data, "bat_capacity", data->cmn.bat_capacity);	
			cJSON_AddNumberToObject(json_data, "fw_vers", data->cmn.fw_vers);
			cJSON_AddItemToObject(json_data, "evse_location", json_location);	
			cJSON_AddNumberToObject(json_location, "lon", data->cmn.location.lon);
			cJSON_AddNumberToObject(json_location, "lat", data->cmn.location.lat);	
			cJSON_AddNumberToObject(json_location, "alt", data->cmn.location.alt);	
			cJSON_AddNumberToObject(json_data, "chg_rate", data->cmn.charge_rate);

			//cloud data
			cJSON_AddNumberToObject(json_data, "chg_stop", data->cloud.charge_stop);
			cJSON_AddNumberToObject(json_data, "tariff_cost", data->cloud.tariff_cost);
			cJSON_AddNumberToObject(json_data, "tariff_rate", data->cloud.tariff_rate);
		}

	}
	
	temp = cJSON_PrintUnformatted(json_message);
	buffer = malloc((strlen(temp)+1)*sizeof(char));
	if(buffer == NULL)
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
						(__LINE__), __func__, errno, strerror(errno));
		LogEvent(client_type, JSON_STRUCTURE_PREP_FAIL, errorBuffer, logFileDesc);
		
		cJSON_Delete(json_message);
		free(temp);
		return buffer;
	}

	strcpy(buffer, temp);
	cJSON_Delete(json_message);
	free(temp);

	return buffer;
}

int RequestData()
{
	char *message = NULL;
	char errorBuffer[ERRNO_MAX_SIZE];
	int i;
	int retCode = 0;

	//redact json message for read command
	message = PrepareJSONStructure(GET_DATA, NULL, ANY);

	printf("Redacted read string to be sent: %s\n", message);

	for(i = 0; i < instance.clients_arr_size; i++)
	{
		retCode = SendMessage(instance.clients_arr[i].fd, message, strlen(message), identity);
		if(retCode == -1)
		{
			sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
			LogEvent(identity, BLANK_ERROR, errorBuffer, logFileDesc);
			free(message);
			return retCode;
		}
		printf("Sent message to socket %i: %s\n", i, message);
	}

	free(message);
	return retCode;
}

void ProcessMessage(int i, char* message, struct evse_data* data){
	cJSON *json_message = NULL;
	cJSON *json_data = NULL;
	EndPoint_t clientType;
	char *temp = NULL;
	char errorBuffer[ERRNO_MAX_SIZE];

	json_message = cJSON_Parse(message);
	if(json_message == NULL)
	{
		sprintf(errorBuffer, "Line: %d in %s. ", (__LINE__), __func__);

		// Get poiner to exact location where JSON string format is incorrect
		const char *errorPtr = cJSON_GetErrorPtr();
        if (errorPtr != NULL)
        {
			sprintf(errorBuffer + strlen(errorBuffer), "Error before: %s", errorPtr);
        }
		LogEvent(identity, JSON_PARSE_FAIL, errorBuffer, logFileDesc);
		
		return;
	}

	clientType =  cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_message, "Client"));

	if(clientType == METER)
	{
		json_data = cJSON_GetObjectItemCaseSensitive(json_message, "Data");
		
		strcpy(data->met.chgsta, cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json_data, "chgsta")));
		
		if(strcmp(data->met.chgsta,"A") == 0)
		{
			strcpy(data->cmn.chg_time, "00H:00M:00S");
			data->cmn.bat_capacity = 0;
		}
		else
		{
			strcpy(data->cmn.chg_time, "01H:26M:40S");
			data->cmn.bat_capacity = 40;
		}

		data->met.current = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_data, "current"));
		data->met.power = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_data, "power"));
		data->met.voltage = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_data, "voltage"));
	}

	if(clientType == NFC){
		json_data = cJSON_GetObjectItemCaseSensitive(json_message, "Data");
		temp = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json_data, "card_id"));
		strcpy(data->nfc.id, temp);
	}

	if(clientType == GUI){
		json_data = cJSON_GetObjectItemCaseSensitive(json_message, "Data");
		data->gui.battery = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_data, "battery_value"));
	}

	if(clientType == CLOUD){
		json_data = cJSON_GetObjectItemCaseSensitive(json_message, "Data");
		data->cloud.charge_stop = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_data, "chg_stop"));
		data->cloud.grid_pwr_lim = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_data, "grid_pwr_lim"));
		data->cloud.tariff_cost = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_data, "tariff_cost"));
		data->cloud.tariff_rate = cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_data, "tariff_rate"));
	}

	cJSON_Delete(json_message);
}

int MainCycle(fd_set *active_fd_set, struct evse_data *data)
{
	fd_set read_fd_set;
	int read_phase[MAX_ENDPOINTS];
	int i;
	int retCode = 0;
	int isComplete = 0;
	char readBuffer[10000];
	char errorBuffer[ERRNO_MAX_SIZE];
	char *message = NULL;

	while(1)
	{
		isComplete = 0;

		// 
		for(i = 0; i < instance.clients_arr_size; i++){
			read_phase[i] = 0;
		}

		// ask clients for data
		retCode = RequestData();
		if(retCode == -1)
		{
			// Server failed to send request message to clients and finishes execution
			return retCode;
		}

		while(!isComplete)
		{
			read_fd_set = *active_fd_set;

			retCode = select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
			if (retCode == -1) 
			{
				sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
						(__LINE__), __func__, errno, strerror(errno));
				LogEvent(identity, FD_SELECT_FAIL, errorBuffer, logFileDesc);
				return retCode;
			}	

			if (retCode > 0)
			{
				for(i = 0; i < instance.clients_arr_size; i++) 
				{
					// Clear read buffer for every client
					memset(readBuffer, 0, sizeof(readBuffer));

					if(read_phase[i] == 0) 
					{
						if(FD_ISSET(instance.clients_arr[i].fd, &read_fd_set))
						{
							retCode = ReadMessage(instance.clients_arr[i].fd, readBuffer, sizeof(readBuffer), identity);
							if(retCode == -1)
							{
								sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
								LogEvent(identity, READ_CLIENT_RESP_FAIL, errorBuffer, logFileDesc);
								return retCode;
							}
							read_phase[i] = 1;
							printf("Read from %d the following message : %s\n", i, readBuffer);
							ProcessMessage(i, readBuffer, data);
						}
					}
				}
			}

			isComplete = 1;

			for(i = 0; i < instance.clients_arr_size; i++)
			{
				if(read_phase[i] == 0) 
				{
					isComplete = 0;
					break;
				}
			}
		}

		// meter push
		if(data->cloud.charge_stop == 1)
		{
			int meterIndex = GetEndpointIndex(METER);

			// check the return of GetEndpointIndex. If it is a valid endpoint index proceed to next lines, 
			// otherwise not execute them.
			if(meterIndex == -1)
			{
				sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
				LogEvent(identity, ENDPOINT_NOT_FOUND, errorBuffer, logFileDesc);
				return meterIndex;
			}

			// prepare JSON message for putting meter in state A
			message = PrepareJSONStructure(PUSH_DATA, data, METER);

			retCode = SendMessage(instance.clients_arr[meterIndex].fd, message, strlen(message), identity);
			if(retCode == -1)
			{
				sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
				LogEvent(identity, BLANK_ERROR, errorBuffer, logFileDesc);
				free(message);
				return retCode;
			}

			printf("Send PUSH_DATA message to meter: %s\n", message);
			free(message);
			
			data->cloud.charge_stop = 0;
		}

		// set charging rate based on cloud input
		if(data->cmn.evse_rating > data->cloud.grid_pwr_lim)
		{
			data->cmn.charge_rate = data->cloud.grid_pwr_lim;
		}		
		else
		{
			data->cmn.charge_rate = data->cmn.evse_rating;
		}

		// calculate charging cost based on cloud input and meter sampled power
		data->cmn.charge_cost = (data->cloud.tariff_cost * data->met.power) / 1000;

		//gui push
		if(isConnected(GUI))
		{
			int guiIndex = GetEndpointIndex(GUI);

			// check the return of GetEndpointIndex. If it is a valid endpoint index proceed to next lines, 
			// otherwise not execute them.
			if(guiIndex == -1)
			{
				sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
				LogEvent(identity, ENDPOINT_NOT_FOUND, errorBuffer, logFileDesc);
				return guiIndex;
			}

			message = PrepareJSONStructure(PUSH_DATA, data, GUI);

			retCode = SendMessage(instance.clients_arr[guiIndex].fd, message, strlen(message), identity);
			if(retCode == -1)
			{
				sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
				LogEvent(identity, BLANK_ERROR, errorBuffer, logFileDesc);
				free(message);
				return retCode;
			}
			printf("Send PUSH_DATA message to gui: %s\n", message);
			free(message);
			
		}
		
		//cloud push
		if(isConnected(CLOUD))
		{
			int cloudIndex = GetEndpointIndex(CLOUD);
		
			// check the return of GetEndpointIndex. If it is a valid endpoint index proceed to next lines, 
			// otherwise not execute them.
			if(cloudIndex == -1)
			{
				sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
				LogEvent(identity, ENDPOINT_NOT_FOUND, errorBuffer, logFileDesc);
				return cloudIndex;
			}
			message = PrepareJSONStructure(PUSH_DATA, data, CLOUD);

			retCode = SendMessage(instance.clients_arr[cloudIndex].fd, message, strlen(message), identity);
			if(retCode == -1)
			{
				sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
				LogEvent(identity, BLANK_ERROR, errorBuffer, logFileDesc);
				free(message);
				return retCode;
			}
			printf("Send PUSH_DATA message to cloud: %s\n", message);
			free(message);

		}
		
		data->cmn.temperature = 30 + (data->cmn.temperature + 1) % 10; 
		LogEvent(identity, SERVER_CYCLE_OK, NULL, logFileDesc);
		sleep(1);
	}
}

void InitEVSE(struct evse_data* data)
{
	char errorBuffer[ERRNO_MAX_SIZE];
	if(data == NULL)
	{
		sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
		LogEvent(identity, EVSE_DATA_INIT_FAIL, errorBuffer, logFileDesc);
		return;
	}
	data->cmn.bat_capacity = 40;
	data->cmn.charge_cost = 0;
	data->cmn.charge_rate = 0;
	strcpy(data->cmn.chg_time,"01H:26M:40S");
	strcpy(data->cmn.evse_id,"0123456789");
	data->cmn.evse_rating = MAX_EVSE_CURRENT;
	data->cmn.fw_vers = 1;
	data->cmn.location.alt = 314.96;
	data->cmn.location.lon = 25.837845529477256;
	data->cmn.location.lat = 45.029858820811924;	
	data->cmn.temperature = 30;
	strcpy(data->cmn.vehicle_auth,"PASS");

	data->cloud.charge_stop = 0;
	data->cloud.grid_pwr_lim = 0;
	data->cloud.tariff_cost = 0;
	data->cloud.tariff_rate = 0;

	data->gui.battery = 0;

	strcpy(data->nfc.id,"");

	strcpy(data->met.chgsta,"A");
	data->met.current = 0;
	data->met.power = 0;
	data->met.voltage = 0;

	LogEvent(identity, EVSE_DATA_INIT_OK, NULL, logFileDesc);
}

int isDenied(EndPoint_t client)
{
	
	for(int i=0;i<instance.deny_list_size;i++)
	{
		if(client == instance.deny_list[i])
		{
			return 1;
		}
	}
	return 0;
}

void DenyClient(EndPoint_t client)
{
	char endpoint[50];
	ConvertEndpointEnumToString(client, endpoint);

	instance.deny_list[instance.deny_list_size++] = client;

	LogEvent(identity, ENDPOINT_DENIED, endpoint, logFileDesc);

}

void AllowClient(EndPoint_t client, char* clientString)
{
	char endpoint[50];
	ConvertEndpointEnumToString(client, endpoint);

	instance.clients_arr[instance.clients_arr_size].type = client;
	instance.clients_arr[instance.clients_arr_size].isConnected = false;
	instance.clients_arr[instance.clients_arr_size].fd = -1;
	instance.clients_arr[instance.clients_arr_size].pid = -1;
	strcpy(instance.clients_arr[instance.clients_arr_size].endpointString, clientString);
	instance.clients_arr_size++;

	LogEvent(identity, ENDPOINT_ALLOWED, endpoint, logFileDesc);

}

int isConnected(EndPoint_t client)
{
	for(int i=0;i<instance.clients_arr_size;i++)
	{
		if(instance.clients_arr[i].type == client && 
			instance.clients_arr[i].isConnected == true)
		{
			return 1;
		}
	}
	return 0;
}

int GetEndpointIndex(EndPoint_t endpointType)
{
	char errorBuffer[ERRNO_MAX_SIZE];
	for(int i=0;i<instance.clients_arr_size;i++)
	{
		if(instance.clients_arr[i].type == endpointType)
		{
			return i;
		}
	}
	return -1;
}

void ServerCleanUp(int signal)
{
	char errorBuffer[ERRNO_MAX_SIZE];
	int signalError = 0;
	int retCode, i;

	if(signal == SIGINT)
	{
		LogEvent(identity, SIGINT_RECEIVED, NULL, logFileDesc);
	}

	if(signal == RUNTIME_ISSUE)
	{
		LogEvent(identity, INTERNAL_ERROR, NULL, logFileDesc);
	}
	
	
	// send SIGUSR1 signal to clients
	for(i=0; i<instance.clients_arr_size; i++)
	{
		// send the termination signal to each client
		retCode = kill(instance.clients_arr[i].pid, SIGUSR1);
		if(retCode == -1)
		{
			signalError = 1;
			sprintf(errorBuffer, "Line: %d in %s. Signaled client: %s, errno: %d - %s", 
					(__LINE__), __func__, instance.clients_arr[i].endpointString, errno, strerror(errno));
			LogEvent(identity, SIGUSR1_SENT_FAIL, errorBuffer, logFileDesc);
		}
	}

	// log event if clients signaling was successful
	if(!signalError)
	{
		LogEvent(identity, SIGUSR1_SENT_OK, NULL, logFileDesc);
	}
	
	// wait for child processes to finish
	for(i=0; i<instance.clients_arr_size; i++)
	{
		waitpid(instance.clients_arr[i].pid, NULL, 0);
	}

	// close server socket file descriptor
	retCode = close(instance.server_fd);
	if(retCode == -1)
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(identity, SOCKET_CLOSE_FAIL, errorBuffer, logFileDesc);
	}
	else
	{
		// remove server.socket file
		LogEvent(identity, SOCKET_CLOSE_OK, NULL, logFileDesc);
		unlink("server.socket");
	}

	// check that logFileDesc is not NULL or stdout
	if(logFileDesc != STDOUT_FD && logFileDesc != -1)
	{
		retCode = close(logFileDesc);
		if(retCode == -1)
		{
			sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
			LogEvent(identity, FD_CLOSE_FAIL, errorBuffer, STDOUT_FD);
		}
		logFileDesc = STDOUT_FD;
	}

	// kill server itself
	retCode = kill(getpid(), SIGKILL);
	if(retCode == -1)
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(identity, SERVER_KILL_FAIL, errorBuffer, logFileDesc);
	}
}

int ParseLoggingLevel(char* buffer)
{
	char errorBuffer[ERRNO_MAX_SIZE];
	char* token;

	// check if the received buffer has LOG_LEVEL property defined
	token = strtok(buffer, "=");
	if(strcmp(token, "LOG_LEVEL"))
	{
		sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
		LogEvent(identity, CONF_FORMAT_INVALID, errorBuffer, logFileDesc);
		return -1;
	}

	// obtain the logging level
	token = strtok(NULL, "\n");
	if(!strcmp(token, "NONE"))
	{
		logLevel = NONE;
		return 0;
	}
	if(!strcmp(token, "ERRORS_ONLY"))
	{
		logLevel = ERRORS_ONLY;
		return 0;
	}
	if(!strcmp(token, "ALL"))
	{
		logLevel = ALL;
		return 0;
	}

	// if logging level is different from above checked levels
	// log the error and return -1
	sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
	LogEvent(identity, CONF_FORMAT_INVALID, errorBuffer, logFileDesc);
	return -1;
}

int ParseConfigFile()
{
	char errorBuffer[ERRNO_MAX_SIZE];
	char lineBuffer[50];
	char clientString[20];
	char* token;
	int clients_no = 0;
	int retCode;
	EndPoint_t clientType;
	FILE* configFile;

	configFile = fopen("evse.conf", "r");
	if(configFile == NULL)
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(identity, CONF_OPEN_FAIL, errorBuffer, logFileDesc);
		return -1;
	}

	// get the first line and determine the logging level
	fgets(lineBuffer, sizeof(lineBuffer), configFile);
	
	// determine the logging level
	retCode = ParseLoggingLevel(lineBuffer);
	if(retCode == -1)
	{
		return retCode;
	}

	// get the next line and determine total clients number
	fgets(lineBuffer, sizeof(lineBuffer), configFile);

	// check config file format. CLIENTS_NO property mandatory on first line
	token = strtok(lineBuffer, "=");
	if(strcmp(token, "CLIENTS_NO"))
	{
		sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
		LogEvent(identity, CONF_FORMAT_INVALID, errorBuffer, logFileDesc);
		return -1;
	}
	// get CLIENTS_NO value
	token = strtok(NULL, "=");
	registeredClientsNo = atoi(token);
	
	// parse the rest of the file for getting client approval state
	while(fgets(lineBuffer, sizeof(lineBuffer), configFile))
	{
		// get client type
		token = strtok(lineBuffer, "=");
		strcpy(clientString, token);

		// convert client string to enum
		clientType = ConvertEndpointStringToEnum(token, identity);
		if(clientType == UNKNOWN_ENDPOINT)
		{
			return -1;
		}
		
		// get client approval state
		token = strtok(NULL, "\n");

		// add client either in allow list, or in denied list
		if(token[0] == 'y')
		{
			AllowClient(clientType, clientString);
		}
		else if(token[0] == 'n')
		{
			DenyClient(clientType);
		}
		else
		{
			sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
			LogEvent(identity, CONF_FORMAT_INVALID, errorBuffer, logFileDesc);
			return -1;
		}
	}
	fclose(configFile);
	return 0;
}

int InitServerInstance()
{
	char errorBuffer[ERRNO_MAX_SIZE];
	int retCode;

	// Initialize instance array sizes and server_fd
	instance.server_fd = -1;
	instance.clients_arr_size = 0;
	instance.deny_list_size = 0;

	
	// populate instance.clients_arr and instance.deny_list arrays from config file
	retCode = ParseConfigFile();
	if(retCode == -1)
	{
		sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
		LogEvent(identity, SERVER_INIT_FAIL, errorBuffer, logFileDesc);
		return retCode;
	}

	LogEvent(identity, SERVER_INIT_OK, NULL, logFileDesc);
	return 0;
}

int main() 
{
	struct evse_data data;
	char clientPath[100];
	char errorBuffer[ERRNO_MAX_SIZE];
	char logLevelArg[8];
	int clientPid;
	int retCode;


	// setup signal handling
	HandleSignal(SIGINT,&ServerCleanUp);	

	// prepare the logging file structure
	PrepareLoggingEnv(identity);
	
	// initialize server instance data structure
	InitServerInstance();

	// initialize EVSE specific data structure
	InitEVSE(&data);

	// initialize server socket
	fd_set active_fd_set;
	instance.server_fd = InitSocketServ(&active_fd_set);
	if(instance.server_fd == -1)
	{
		return instance.server_fd;
	}

	// start clients processes 
	sprintf(logLevelArg,"%d",logLevel);
	for(int i=0;i<instance.clients_arr_size;i++)
	{
		clientPid = fork();
		// client procedure
		if(clientPid == 0)
		{
			strcpy(clientPath, instance.clients_arr[i].endpointString);
			int retCode = execl(clientPath, clientPath, logLevelArg, NULL);
			if(retCode == -1)
			{
				sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
						(__LINE__), __func__, errno, strerror(errno));
				LogEvent(identity, EXEC_CLIENT_FAIL, errorBuffer, logFileDesc);
			}
		}
		// server procedure
		else if(clientPid != -1)
		{
			// save client pid in instance structure
			instance.clients_arr[i].pid = clientPid;
		}
		// fork() error -- returned -1
		else
		{
			sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
					(__LINE__), __func__, errno, strerror(errno));
			LogEvent(identity, FORK_CLIENT_FAIL, errorBuffer, logFileDesc);
		}
	}

	// establish server - clients connections
	retCode = ClientHandshake(&active_fd_set);
	if(retCode == -1)
	{
		return retCode;
	}

	// run the server mail_cycle procedure
	MainCycle(&active_fd_set, &data);

	// Do the cleanup before exit
	ServerCleanUp(RUNTIME_ISSUE);
	return 0;
}
