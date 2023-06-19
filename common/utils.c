/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/

#include "../include/utils.h"

// log file descriptor defined by each client
extern int logFileDesc;

// client's identity defined in their dedicated source file
extern EndPoint_t identity;

// client's file descriptor used in socket communication
extern int endpointFd;

void GetTime(struct tm *dateTime)
{
	time_t timestamp = time(NULL);
	*dateTime = *localtime(&timestamp);
}

int ConvertEndpointEnumToString(EndPoint_t logSource, char *logSourceString)
{
	char errorBuffer[ERRNO_MAX_SIZE];
	int logSourceFound = 1;

	switch (logSource)
	{
	case METER:
		strcpy(logSourceString, "METER");
		break;
	case GUI:
		strcpy(logSourceString, "GUI");
		break;
	case NFC:
		strcpy(logSourceString, "NFC");
		break;
	case CLOUD:
		strcpy(logSourceString, "CLOUD");
		break;
	case SERVER:
		strcpy(logSourceString, "SERVER");
		break;
	case UNKNOWN_ENDPOINT:
		strcpy(logSourceString, "UnknownEndpoint");
		logSourceFound = -1;
	default:
		logSourceFound = -1;
		sprintf(errorBuffer, "Line: %d in %s. Client enum to string conversion failed.", (__LINE__), __func__);
		LogEvent(logSource, ENDPOINT_NOT_FOUND, errorBuffer, logFileDesc);
		break;
	}

	return logSourceFound;
}

int ConvertEndpointStringToEnum(char *clientString, EndPoint_t loggingSource)
{
	char errorBuffer[ERRNO_MAX_SIZE];

	if (strcmp(clientString, "METER") == 0)
		return METER;

	if (strcmp(clientString, "NFC") == 0)
		return NFC;

	if (strcmp(clientString, "CLOUD") == 0)
		return CLOUD;

	if (strcmp(clientString, "GUI") == 0)
		return GUI;

	sprintf(errorBuffer, "Line: %d in %s. Client string to enum conversion failed.", (__LINE__), __func__);
	LogEvent(loggingSource, ENDPOINT_NOT_FOUND, errorBuffer, logFileDesc);
	return UNKNOWN_ENDPOINT;
}

void ParseJSONMessage(char *message, int *flags, EndPoint_t loggingSource)
{
	char errorBuffer[ERRNO_MAX_SIZE];
	cJSON *json_data = NULL;
	const char *errorPtr;
	ClientAction_t op_type;

	json_data = cJSON_Parse(message);
	if (json_data == NULL)
	{
		sprintf(errorBuffer, "Line: %d in %s. JSON string parsing failed. ", (__LINE__), __func__);

		// Get poiner to exact location where JSON string format is incorrect
		errorPtr = cJSON_GetErrorPtr();
		if (errorPtr != NULL)
		{
			sprintf(errorBuffer + strlen(errorBuffer), "Error before: %s", errorPtr);
		}
		LogEvent(loggingSource, JSON_PARSE_FAIL, errorBuffer, logFileDesc);

		return;
	}

	op_type = (int)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_data, "Type"));

	switch (op_type)
	{
	case GET_DATA:
		flags[GET_DATA] = 1;
		break;

	case PUSH_DATA:
		flags[PUSH_DATA] = 1;
		break;

	default:
		break;
	}

	cJSON_Delete(json_data);
	LogEvent(loggingSource, JSON_PARSE_OK, NULL, logFileDesc);
	return;
}

void __attribute__((weak)) CleanUp(int signal)
{
	int retCode;
	char errorBuffer[ERRNO_MAX_SIZE];

	if(signal == SIGUSR1)
	{
		LogEvent(identity, SIGUSR1_RECEIVED_OK, NULL, logFileDesc);
	}
	
	if(signal == RUNTIME_ISSUE)
	{
		LogEvent(identity, INTERNAL_ERROR, NULL, logFileDesc);
	}

	// close endpoint socket file descriptor
	retCode = close(endpointFd);
	if (retCode == -1)
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(identity, SOCKET_CLOSE_FAIL, errorBuffer, logFileDesc);
	}
	else
	{
		LogEvent(identity, SOCKET_CLOSE_OK, NULL, logFileDesc);
	}

	// check that logFileDesc is not NULL or stdout
	if (logFileDesc != STDOUT_FD && logFileDesc != -1)
	{
		retCode = close(logFileDesc);
		if (retCode == -1)
		{
			sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
					(__LINE__), __func__, errno, strerror(errno));
			LogEvent(identity, FD_CLOSE_FAIL, errorBuffer, STDOUT_FD);
		}
		logFileDesc = STDOUT_FD;
	}

	// kill the process itself
	retCode = kill(getpid(), SIGKILL);
	if (retCode == -1)
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(identity, CLIENT_KILL_FAIL, errorBuffer, logFileDesc);
	}
}

int LoadVariable(const char *variableName, char *variableValue, size_t valueSize)
{
	FILE *file = fopen(CLOUD_CONF_FILE, "r");
	if (file == NULL)
	{
		fprintf(stderr, "Failed to open %s - File should be created and populated before running.\n", CLOUD_CONF_FILE);
		return -1;
	}

	char line[MAX_LINE_LENGTH];
	char *var;
	while (fgets(line, sizeof(line), file) != NULL)
	{
		var = strstr(line, variableName);
		if (var != NULL)
		{
			// Extract the value after the equals sign (Retrieve the variable value itself)
			char *tokenPointer = strchr(line, '=');
			// If it is a valid value
			if (tokenPointer != NULL)
			{
				// Copy the value from the '=' token on.
				strcpy(variableValue, tokenPointer + 1);
				// Replace the '\n' char brought from the file by the '\0' (end of string)
				tokenPointer = strchr(variableValue, '\n');
				*tokenPointer = '\0';
				break;
			}
		}
	}

	fclose(file);
}

int UpdateConfigFile(const char *variableName, const char *newValue, const char *newVariable)
{
	char line[MAX_LINE_LENGTH];
	int variableUpdated = 0;
	FILE *file = fopen(CLOUD_CONF_FILE, "r");
	if (file == NULL)
	{
		fprintf(stderr, "Failed to open file: %s\n", CLOUD_CONF_FILE);
		return -1;
	}

	// Create a temporary file to write updated contents
	char tempFileName[] = "temp_cloud_conf";
	FILE *tempFile = fopen(tempFileName, "w");
	if (tempFile == NULL)
	{
		fprintf(stderr, "Failed to create temporary file\n");
		fclose(file);
		return -1;
	}

	// Read each line of the original file
	while (fgets(line, MAX_LINE_LENGTH, file) != NULL)
	{
		// Find the line that starts with the target variable name
		if (strncmp(line, variableName, strlen(variableName)) == 0)
		{
			// Update the value of the target variable
			fprintf(tempFile, "%s=%s\n", variableName, newValue);
			variableUpdated = 1;
		}
		else
		{
			// Copy the line as it is to the temporary file
			fputs(line, tempFile);
		}
	}

	// Add the new variable at the end if it was not updated
	if (!variableUpdated)
	{
		fprintf(tempFile, "%s=%s\n", newVariable, newValue);
	}

	// Close the files
	fclose(file);
	fclose(tempFile);

	// Replace the original file with the temporary file
	if (remove(CLOUD_CONF_FILE) != 0)
	{
		fprintf(stderr, "Failed to remove original file: %s\n", CLOUD_CONF_FILE);
		return -1;
	}
	if (rename(tempFileName, CLOUD_CONF_FILE) != 0)
	{
		fprintf(stderr, "Failed to rename temporary file\n");
		return -1;
	}
}