/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/

#include "easyevse/utils.h"

// log file descriptor defined by each client
extern int logFileDesc;

// client's identity defined in their dedicated source file
extern EndPoint_t identity;

int ConvertEndpointEnumToString(EndPoint_t logSource, char *logSourceString)
{
	char errorBuffer[ERRNO_MAX_SIZE];
	int logSourceFound = 1;

	switch (logSource)
	{

	case UART_BRIDGE:
		strcpy(logSourceString, "UART_BRIDGE");
		break;	
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

void GetTime(struct tm *dateTime)
{
	time_t timestamp = time(NULL);
	*dateTime = *localtime(&timestamp);
}

int LoadVariable(const char *fileName, const char *variableName, char *variableValue, size_t valueSize)
{
	bool foundValue = false;
	char line[MAX_LINE_LENGTH];
	char *var, *tokenPointer, errorBuffer[ERRNO_MAX_SIZE];
	FILE *file;

	file = fopen(fileName, "r");
	if(file == NULL)
	{
		sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s", 
				(__LINE__), __func__, errno, strerror(errno));
		LogEvent(identity, CONF_OPEN_FAIL, errorBuffer, logFileDesc);
		return -1;
	}

	while (fgets(line, sizeof(line), file) != NULL)
	{
		var = strstr(line, variableName);
		if (var != NULL)
		{
			// Extract the value after the equals sign (Retrieve the variable value itself)
			tokenPointer = strchr(line, '=');
			// If it is a valid value
			if (tokenPointer != NULL)
			{
				// Copy the value from the '=' token on.
				strcpy(variableValue, tokenPointer + 1);
				// Replace the '\n' char brought from the file by the '\0' (end of string)
				tokenPointer = strchr(variableValue, '\n');
				*tokenPointer = '\0';
				foundValue = true;
				break;
			}
			else
			{
				sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
				LogEvent(identity, CONF_FORMAT_INVALID, errorBuffer, logFileDesc);
				return -1;
			}
		}
	}

	if(!foundValue)
	{
		sprintf(errorBuffer, "Line: %d in %s", (__LINE__), __func__);
		LogEvent(identity, CONF_FORMAT_INVALID, errorBuffer, logFileDesc);
		return -1;	
	}

	fclose(file);
}

int UpdateConfigFile(const char *fileName, const char *variableName, const char *newValue, const char *newVariable)
{
	FILE *file, *tempFile;
	char line[MAX_LINE_LENGTH], tempFileName[MAX_FILENAME_LENGTH];
	int variableUpdated = 0;

	file = fopen(fileName, "r");
	if (file == NULL)
	{
		fprintf(stderr, "Failed to open file: %s\n", fileName);
		return -1;
	}

	// Create a temporary file to write updated contents
	
	sprintf(tempFileName,"temp_%s",fileName);
	
	tempFile = fopen(tempFileName, "w");
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
	if (remove(fileName) != 0)
	{
		fprintf(stderr, "Failed to remove original file: %s\n", fileName);
		return -1;
	}
	if (rename(tempFileName, fileName) != 0)
	{
		fprintf(stderr, "Failed to rename temporary file\n");
		return -1;
	}
}
