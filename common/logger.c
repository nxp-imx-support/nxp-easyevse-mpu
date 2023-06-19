/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/


#include "../include/logger.h"

extern LoggingLevel_t logLevel;
extern int logFileDesc;

void ErrorCodeToStringMapping(int errorCode, char* errorString)
{
    switch (errorCode)
    {
    case CLIENT_NAME_UNKNOWN:
        strcpy(errorString, "Failed to get client name string.");
        break;
    case MALLOC_ERROR:
        strcpy(errorString, "Failed to allocate memory using malloc.");
        break;
    case SOCKET_CREATION_FAIL:
        strcpy(errorString, "Failed to create the client socket.");
        break;
    case SOCKET_CONNECTION_FAIL:
        strcpy(errorString, "Failed to establish socket connection.");
        break;
    case CLIENT_CONVERT_FAIL:
        strcpy(errorString, "Failed to convert client string to enum.");
        break;
    case READ_ERROR:
        strcpy(errorString, "Failed to read from socket.");
        break;
    case ENDPOINT_NOT_FOUND:
        strcpy(errorString, "Endpoint could not be found.");
        break;
    case SEND_MESSAGE_FAIL:
        strcpy(errorString, "Failed to send message.");
        break;
    case SEND_IDENTITY_FAIL:
        strcpy(errorString, "Failed to send identity.");
        break;
    case READ_FAIL:
        strcpy(errorString, "Failed to read from socket.");
        break;
    case SERIAL_INIT_FAIL:
        strcpy(errorString, "Failed to initialize serial port.");
        break;
    case SOCKET_BIND_FAIL:
        strcpy(errorString, "Failed to bind socket to its sockaddr.");
        break;
    case SOCKET_LISTEN_FAIL:
        strcpy(errorString, "Socket failed to enter in listen mode.");
        break;
    case SOCKET_ACCEPT_FAIL:
        strcpy(errorString, "Socket failed to accept new connection.");
        break;
    case FD_SELECT_FAIL:
        strcpy(errorString, "select() returned an error. More details from following errno code.");
        break;
    case SERVER_INIT_FAIL:
        strcpy(errorString, "Failed to initialize server instance.");
        break;
    case FD_CLOSE_FAIL:
        strcpy(errorString, "Failed to close file descriptor.");
        break;
    case EVSE_DATA_INIT_FAIL:
        strcpy(errorString, "EVSE data structure initialization failed.");
        break;
    case FD_OPEN_FAIL:
        strcpy(errorString, "Failed to open specified file.");
        break;
    case FORK_CLIENT_FAIL:
        strcpy(errorString, "fork() returned an error. More details from following errno code.");
        break;
    case CONF_OPEN_FAIL:
        strcpy(errorString, "Failed to open configuration file. Be sure file named 'evse.conf' is located in the same directory with server binary");
        break;
    case CONF_FORMAT_INVALID:
        strcpy(errorString, "Configuration file format is invalid.");
        break;
    case EXEC_CLIENT_FAIL:
        strcpy(errorString, "Failed to execute client binary.");
        break;
    case SIGUSR1_SENT_FAIL:
        strcpy(errorString, "Sending SIGUSR1 to client failed.");
        break;
    case CLIENT_KILL_FAIL:
        strcpy(errorString, "Client failed to kill itself.");
        break;
    case SOCKET_CLOSE_FAIL:
        strcpy(errorString, "Failed to close socket file descriptor.");
        break;
    case READ_CLIENT_RESP_FAIL:
        strcpy(errorString, "Failed to read client response.");
        break;
    case BLANK_ERROR:
        strcpy(errorString, "");
        break;
    case JSON_PARSE_FAIL:
        strcpy(errorString, "JSON string parsing failed.");
        break;
    case JSON_STRUCTURE_PREP_FAIL:
        strcpy(errorString, "JSON structure preparation failed.");
        break;
    case SERVER_KILL_FAIL:
        strcpy(errorString, "Server failed to kill itself.");
        break;
    case CLIENT_HANDSHAKE_FAIL:
        strcpy(errorString, "Handshake message reading failed.");
        break;
    case NFC_THREAD_CREATION_FAIL:
        strcpy(errorString, "NFC client thread creation failed.");
        break;
    case IOTHUB_INIT_FAIL:
        strcpy(errorString, "Failed to IoTHub_Init().");
        break;
    case IOTHUB_CONN_CALL_FAIL:
        strcpy(errorString, "Failed to configure the connection status callback.");
        break;
    case PROV_SEC_INIT_FAIL:
        strcpy(errorString, "Failed to prov_dev_security_init.");
        break;
    case PROV_SET_SK_FAIL:
        strcpy(errorString, "Failed to set Symmetric Key Info.");
        break;
    case PROV_DEV_CREATE_FAIL:
        strcpy(errorString, "Failed to create device handle via DPS service.");
        break;
    case PROV_DEV_REG_FAIL:
        strcpy(errorString, "Failed to Prov_Device_Register_Device().");
        break;
    case IOTHUB_SET_INIT_FAIL:
        strcpy(errorString, "Failed to iothub_security_init().");
        break;
    case CREATE_DEV_HANDLE_FAIL_AUTH:
        strcpy(errorString, "Failed to IoTHubDeviceClient_CreateFromDeviceAuth().");
        break;
    case CREATE_DEV_HANDLE_FAIL_CS:
        strcpy(errorString, "Failed to IoTHubDeviceClient_CreateFromConnectionString().");
        break;
    case IOTHUB_METH_INVOC_FAIL:
        strcpy(errorString, "Failed to IoTHubDeviceClient_SetDeviceMethodCallback().");
        break;
    case IOTHUB_GET_TWIN_FAIL:
        strcpy(errorString, "Failed to IoTHubDeviceClient_GetTwinAsync().");
        break;
    case IOTHUB_SET_TWIN_CALL_FAIL:
        strcpy(errorString, "Failed to IoTHubDeviceClient_SetDeviceTwinCallback().");
        break;
    case GET_ENV_FAIL:
        strcpy(errorString, "Failed to retrieve variable environment.");
        break;
    case PROV_TYPE_INVALID:
        strcpy(errorString, "Provisioning type passed by configuration file is invalid.");
        break;
    case CJSON_PRINT_MESSAGE_FAIL:
        strcpy(errorString, "Failed to allocate and print cJSON message into buffer.");
        break;
    default:
        strcpy(errorString, "Error code to string conversion failed.");
        break;
    }
}

void LoggingCodeToStringMapping(int logCode, char *logString)
{
    switch (logCode)
    {
    case SOCKET_CREATION_OK:
        strcpy(logString, "Socket successfully created.");
        break;
    case CLIENT_INIT_OK:
        strcpy(logString, "Client successfully initialized.");
        break;
    case SERVER_INIT_OK:
        strcpy(logString, "Server successfully initialized.");
        break;    
    case SEND_MESSAGE_OK:
        strcpy(logString, "Message successfully sent.");
        break;
    case SEND_IDENTITY_OK:
        strcpy(logString, "Identity successfully sent.");
        break;
    case SOCKET_CONNECTION_OK:
        strcpy(logString, "Socket connection successfully established.");
        break;
    case READ_OK:
        strcpy(logString, "Successfully read from socket.");
        break;
    case JSON_PARSE_OK:
        strcpy(logString, "Successfully parsed JSON message.");
        break;
    case SERIAL_INIT_OK:
        strcpy(logString, "Successfully initialized serial port.");
        break;
    case PARSE_METER_DATA_OK:
        strcpy(logString, "Successfully parsed meter data.");
        break;
    case SEND_JSON_DATA_OK:
        strcpy(logString, "Successfully sent JSON data.");
        break;
    case SERVER_CYCLE_OK:
        strcpy(logString, "Successfully finished new cycle.");
        break;
    case CLIENTS_HANDSHAKE_OK:
        strcpy(logString, "Successfully handshake with all clients.");
        break;
    case EVSE_DATA_INIT_OK:
        strcpy(logString, "EVSE data structure was initialized with success.");
        break;
    case SOCKET_BIND_OK:
        strcpy(logString, "Socket - sockaddr binded with success.");
        break; 
    case SOCKET_LISTEN_OK:
        strcpy(logString, "Socket is listening.");
        break;
    case SOCKET_ACCEPT_OK:
        strcpy(logString, "Socket accepted a new connection.");
        break;
    case ENDPOINT_DENIED:
        strcpy(logString, "Endpoint was denied.");
        break;
    case JSON_PREPARE_OK:
        strcpy(logString, "JSON message successfully prepared.");
        break;
    case SIGUSR1_RECEIVED_OK:
        strcpy(logString, "SIGUSR1 signal received.");
        break;
    case ENDPOINT_ALLOWED:
        strcpy(logString, "Endpoint was allowed.");
        break; 
    case SIGINT_RECEIVED:
        strcpy(logString, "SIGINT signal received.");
        break;
    case SIGUSR1_SENT_OK:
        strcpy(logString, "SIGUSR1 signal successfully sent to clients.");
        break;
    case SOCKET_CLOSE_OK:
        strcpy(logString, "Socket file descriptor successfully removed.");
        break;
    case NFC_STACK_INIT_OK: 
        strcpy(logString, "NFC stack initialized successfully.");
        break;
    case NFC_THREAD_CREATION_OK:
        strcpy(logString, "NFC client thread created successfully.");
        break;
    case INTERNAL_ERROR:
        strcpy(logString, "Process killed due to an internal error.");
        break;
    default:
        strcpy(logString, "Logging code to string conversion failed.");
        break;
    }
}

void LogEvent(EndPoint_t logSource, int loggingCode, char* additionalInfo, int logFileDesc)
{
    if(logLevel == NONE)
    {
        return;
    }

    char errCodeExplStr[ERRORCODE_EXPLANATION_STRING_SIZE];
    char sourceStr[LOGGING_SOURCE_STRING_SIZE];
    char timeStr[TIME_STRING_SIZE];
    char outputStr[OUTPUT_STRING_SIZE];

    // convert Client_t logSource to loggingSource string and check if a matching client was found
    if(ConvertEndpointEnumToString(logSource, sourceStr)  == -1)
    {
        ErrorCodeToStringMapping(CLIENT_NAME_UNKNOWN, errCodeExplStr);
        PrintLoggingTimeInfo(timeStr);
        sprintf(outputStr, "%s-[Logger] Error code: %d: %s ", timeStr, loggingCode, errCodeExplStr);
        write(logFileDesc, outputStr, strlen(outputStr));
        return;
    }

    // Build logging message
    if(ERROR_BASE < loggingCode && loggingCode< LOG_BASE) // inside error code range
    {
        // Error branch
        if(logLevel >= ERRORS_ONLY) // Check logging level
        {
            ErrorCodeToStringMapping(loggingCode, errCodeExplStr);
            PrintLoggingTimeInfo(timeStr);
            sprintf(outputStr, "%s-[%s] Error code: %d: %s ", timeStr, sourceStr, loggingCode, errCodeExplStr);

            if(additionalInfo != NULL)
            {
                strcat(outputStr, additionalInfo);
            }
        
            strcat(outputStr, "\n");
            write(logFileDesc, outputStr, strlen(outputStr));
        }
    }
    else // outside error code range --> log code
    {  
        // Log branch
        if(logLevel >= ALL)
        {
            LoggingCodeToStringMapping(loggingCode, errCodeExplStr);
            PrintLoggingTimeInfo(timeStr);
            sprintf(outputStr, "%s-[%s] Logging code: %d: %s ", timeStr, sourceStr, loggingCode, errCodeExplStr);

            if(additionalInfo != NULL)
            {
                strcat(outputStr, additionalInfo);
            }
        
            strcat(outputStr, "\n");
            write(logFileDesc, outputStr, strlen(outputStr));
        }
    }   
}

void PrintLoggingTimeInfo(char* timeString)
{
    struct tm dateTime;
    GetTime(&dateTime);

    sprintf(timeString, 
            "[%d-%02d-%02d@%02d:%02d:%02d] ", 
            dateTime.tm_year+1900, 
            dateTime.tm_mon+1, 
            dateTime.tm_mday, 
            dateTime.tm_hour, 
            dateTime.tm_min, 
            dateTime.tm_sec
        );
}

int PrepareLoggingEnv(EndPoint_t logSource)
{
    char logSourceString[32];
    char errorBuffer[ERRNO_MAX_SIZE];
    int retCode = 0;

    // get endpoint type in string format
    retCode = ConvertEndpointEnumToString(logSource,logSourceString);
    if(retCode == -1)
    {
        // if endpoint enum to string conversion fails --> return from function
        // default logging file descriptor is used (STDOUT_FD)
        return retCode;
    }

    // make logs dir in case it does not exist
	struct stat st = {0};
	if (stat("logs", &st) == -1) 
	{
		mkdir("logs", 0754);
	}

    // build log file path string
    char logFilePath[100];
	struct tm dt;
	GetTime(&dt);
	sprintf(logFilePath, "logs/%s_%d%02d%02d_%02d%02d%02d.log", 
			logSourceString, dt.tm_year + 1900, dt.tm_mon + 1, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec);
	
	// create the log file with rw-rw-r-- permissions and get its file descriptor
	logFileDesc = open(logFilePath, O_WRONLY | O_CREAT,0664);
    if(logFileDesc == -1)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(logSource, FD_OPEN_FAIL, errorBuffer, STDOUT_FD);
		return logFileDesc;
    }

    return retCode;
}

	