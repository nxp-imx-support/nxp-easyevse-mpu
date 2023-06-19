/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/


#pragma once
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/stat.h>
#include "typedefs.h"
#include "comms.h"
#include "utils.h"

// Useful defines
#define LOGGING_SOURCE_STRING_SIZE          50                          // Logging source name string max size
#define LOGGER_BASE_CODE                    20000                       // Set minimum value for an logging event
#define ERRORCODE_EXPLANATION_STRING_SIZE   100                         // Error string max size
#define CODE_EXPLANATION_STRING_SIZE        200                         // Logging string max size
#define OUTPUT_STRING_SIZE                  1024                        // Max string size of logger output
#define TIME_STRING_SIZE                    50                          // Max string size of date and time information


// Error codes     
// Range [ERROR_BASE;LOG_BASE] 
// --> 200 error codes available to be defined

#define ERROR_BASE                          LOGGER_BASE_CODE            // Base for error codes
#define MALLOC_ERROR                        (ERROR_BASE + 1)            // Failed to allocate memory using malloc
#define CLIENT_NAME_UNKNOWN                 (ERROR_BASE + 2)            // Failed to get client name string
#define SOCKET_CREATION_FAIL                (ERROR_BASE + 3)            // Failed to create the client socket            
#define SOCKET_CONNECTION_FAIL              (ERROR_BASE + 4)            // Socket connection failed
#define CLIENT_CONVERT_FAIL                 (ERROR_BASE + 5)            // Failed to identify the client connected
#define READ_ERROR                          (ERROR_BASE + 6)            // Failed to read from socket
#define ENDPOINT_NOT_FOUND                  (ERROR_BASE + 7)            // Endpoint could not be found
#define SEND_MESSAGE_FAIL                   (ERROR_BASE + 8)            // Failed to send message
#define SEND_IDENTITY_FAIL                  (ERROR_BASE + 9)            // Failed to send identity
#define READ_FAIL                           (ERROR_BASE + 10)           // Failed to read from socket
#define SERIAL_INIT_FAIL                    (ERROR_BASE + 11)           // Failed to initialize serial port
#define SOCKET_BIND_FAIL                    (ERROR_BASE + 12)           // Failed to bind socket to its sockaddr
#define SOCKET_LISTEN_FAIL                  (ERROR_BASE + 13)           // Socket failed to enter in listen mode
#define SOCKET_ACCEPT_FAIL                  (ERROR_BASE + 14)           // Socket failed to accept new connection
#define FD_SELECT_FAIL                      (ERROR_BASE + 15)           // select() returned an error. More details from following errno code.
#define SERVER_INIT_FAIL                    (ERROR_BASE + 16)           // Failed to initialize server instance
#define FD_CLOSE_FAIL                       (ERROR_BASE + 17)           // Failed to close file descriptor
#define EVSE_DATA_INIT_FAIL                 (ERROR_BASE + 18)           // EVSE data structure initialization failed
#define FD_OPEN_FAIL                        (ERROR_BASE + 19)           // Failed to open specified file.
#define FORK_CLIENT_FAIL                    (ERROR_BASE + 20)           // fork() returned an error. More details from following errno code
#define CONF_OPEN_FAIL                      (ERROR_BASE + 21)           // Failed to open configuration file. Be sure file named 'evse.conf'is located in the same directory with server binary
#define CONF_FORMAT_INVALID                 (ERROR_BASE + 22)           // Configuration file format is invalid
#define EXEC_CLIENT_FAIL                    (ERROR_BASE + 23)           // Failed to execute client binary
#define SIGUSR1_SENT_FAIL                   (ERROR_BASE + 24)           // Sending SIGUSR1 to client failed
#define CLIENT_KILL_FAIL                    (ERROR_BASE + 25)           // Client failed to kill itself
#define SOCKET_CLOSE_FAIL                   (ERROR_BASE + 26)           // Failed to close socket file descriptor 
#define READ_CLIENT_RESP_FAIL               (ERROR_BASE + 27)           // Failed to read client response
#define BLANK_ERROR                         (ERROR_BASE + 28)           // Blank error code
#define JSON_PARSE_FAIL                     (ERROR_BASE + 29)           // JSON string parsing failed
#define JSON_STRUCTURE_PREP_FAIL            (ERROR_BASE + 30)           // JSON structure preparation failed
#define SERVER_KILL_FAIL                    (ERROR_BASE + 31)           // Server failed to kill itself
#define CLIENT_HANDSHAKE_FAIL               (ERROR_BASE + 32)           // Handshake message reading failed
#define NFC_THREAD_CREATION_FAIL            (ERROR_BASE + 33)           // Failed to create the NFC client thread
#define IOTHUB_INIT_FAIL                    (ERROR_BASE + 34)           // Failed to IoTHub_Init()
#define IOTHUB_CONN_CALL_FAIL               (ERROR_BASE + 35)           // Failed to configure the connection status callback
#define PROV_SEC_INIT_FAIL                  (ERROR_BASE + 36)           // Failed to prov_dev_security_init
#define PROV_SET_SK_FAIL                    (ERROR_BASE + 37)           // Failed to set Symmetric Key Info
#define PROV_DEV_CREATE_FAIL                (ERROR_BASE + 38)           // Failed to create device handle via DPS service
#define PROV_DEV_REG_FAIL                   (ERROR_BASE + 39)           // Failed to Prov_Device_Register_Device()
#define IOTHUB_SET_INIT_FAIL                (ERROR_BASE + 40)           // Failed to iothub_security_init()
#define CREATE_DEV_HANDLE_FAIL_AUTH         (ERROR_BASE + 41)           // Failed to IoTHubDeviceClient_CreateFromDeviceAuth()
#define CREATE_DEV_HANDLE_FAIL_CS           (ERROR_BASE + 42)           // Failed to IoTHubDeviceClient_CreateFromConnectionString()
#define IOTHUB_METH_INVOC_FAIL              (ERROR_BASE + 43)           // Failed to IoTHubDeviceClient_SetDeviceMethodCallback()
#define IOTHUB_GET_TWIN_FAIL                (ERROR_BASE + 44)           // Failed to IoTHubDeviceClient_GetTwinAsync()
#define IOTHUB_SET_TWIN_CALL_FAIL           (ERROR_BASE + 45)           // Failed to IoTHubDeviceClient_SetDeviceTwinCallback()
#define GET_ENV_FAIL                        (ERROR_BASE + 46)           // Failed to retrieve variable environment
#define PROV_TYPE_INVALID                   (ERROR_BASE + 47)           // Provisioning type passed by configuration file is invalid
#define CJSON_PRINT_MESSAGE_FAIL            (ERROR_BASE + 48)           // Failed to allocate and print cJSON message into buffer


// Logging code
// Range [LOG_BASE; inf]     
#define LOG_BASE                            (LOGGER_BASE_CODE + 200)    // Code base for logging
#define SOCKET_CREATION_OK                  (LOG_BASE + 1)              // Socket successfully created
#define CLIENT_INIT_OK                      (LOG_BASE + 2)              // Client successfully initialized
#define SERVER_INIT_OK                      (LOG_BASE + 3)              // Server successfully initialized
#define SEND_MESSAGE_OK                     (LOG_BASE + 4)              // Message successfully sent
#define SEND_IDENTITY_OK                    (LOG_BASE + 5)              // Identity successfully sent
#define SOCKET_CONNECTION_OK                (LOG_BASE + 6)              // Socket connection successfully established
#define READ_OK                             (LOG_BASE + 7)              // Successfully read from socket
#define JSON_PARSE_OK                       (LOG_BASE + 8)              // Successfully parsed JSON message
#define SERIAL_INIT_OK                      (LOG_BASE + 9)              // Successfully initialized serial port
#define PARSE_METER_DATA_OK                 (LOG_BASE + 10)             // Successfully parsed meter data
#define SEND_JSON_DATA_OK                   (LOG_BASE + 11)             // Successfully sent JSON data
#define SERVER_CYCLE_OK                     (LOG_BASE + 12)             // Successfully finished new cycle
#define CLIENTS_HANDSHAKE_OK                (LOG_BASE + 13)             // Successfully handshake with all clients
#define EVSE_DATA_INIT_OK                   (LOG_BASE + 14)             // EVSE data structure was initialized with success
#define SOCKET_BIND_OK                      (LOG_BASE + 15)             // Socket - sockaddr binded with success
#define SOCKET_LISTEN_OK                    (LOG_BASE + 16)             // Socket is listening
#define SOCKET_ACCEPT_OK                    (LOG_BASE + 17)             // Socket accepted a new connection
#define ENDPOINT_DENIED                     (LOG_BASE + 18)             // Endpoint was denied
#define JSON_PREPARE_OK                     (LOG_BASE + 19)             // JSON message successfully prepared
#define SIGUSR1_RECEIVED_OK                 (LOG_BASE + 20)             // SIGUSR1 signal received
#define SIGINT_RECEIVED                     (LOG_BASE + 21)             // SIGINT signal received
#define ENDPOINT_ALLOWED                    (LOG_BASE + 22)             // Endpoint was allowed
#define SIGUSR1_SENT_OK                     (LOG_BASE + 23)             // SIGUSR1 signal successfully sent to clients
#define SOCKET_CLOSE_OK                     (LOG_BASE + 24)             // Socket file descriptor successfully removed
#define NFC_STACK_INIT_OK                   (LOG_BASE + 25)             // Successfully initialization of the NFC stack  
#define NFC_THREAD_CREATION_OK              (LOG_BASE + 26)             // NFC client thread successfully created 
#define INTERNAL_ERROR                      (LOG_BASE + 27)             // Process killed due to an internal error




void    ErrorCodeToStringMapping(int errorCode, char* errorString);
void    LoggingCodeToStringMapping(int logCode, char* logString);
void    LogEvent(EndPoint_t logSource, int loggingCode, char* additionalInfo, int logFileDesc);
void    PrintLoggingTimeInfo(char* timeString);
int     PrepareLoggingEnv(EndPoint_t logSource);
