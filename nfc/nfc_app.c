/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/

#include "../include/comms.h"
#include <cjson/cJSON.h>
#include "../include/nfc_api.h"

// Log file descriptor
// default logging output is stdout
volatile int logFileDesc = STDOUT_FD;

// Logging level
LoggingLevel_t logLevel = ALL;

// NFC identity variable defined only in nfc_app.c
EndPoint_t identity = NFC;

// NFC socket file descriptor
int endpointFd;

void cmd_poll()
{
    int res = 0x00;

    InitEnv();

    res = InitMode(0x01, 0x01, 0x00);

    if (0x00 == res)
    {
        LogEvent(NFC, NFC_STACK_INIT_OK, NULL, logFileDesc);
        WaitDeviceArrival(0x01, NULL, 0x00);
    }

    DeinitPollMode();
}

char *PrepareJSONMessage()
{
    char *buffer = NULL;
    cJSON *json_data = NULL;
    cJSON *json_nfcdata = NULL;
    int res;

    json_data = cJSON_CreateObject();
    json_nfcdata = cJSON_CreateObject();

    cJSON_AddNumberToObject(json_data, "Client", identity);
    cJSON_AddItemToObject(json_data, "Data", json_nfcdata);
    sem_wait(&semaphore);
    cJSON_AddStringToObject(json_nfcdata, "card_id", g_TagInfo.uid);
    sem_post(&semaphore);

    buffer = cJSON_PrintUnformatted(json_data);
    cJSON_Delete(json_data);

    LogEvent(identity, JSON_PREPARE_OK, NULL, logFileDesc);

    return buffer;
}

bool exit_nfc_thread = false;

void UpdateCycle()
{
    char messageBuffer[10000];
    int flags[] = {0, 0};
    int retCode;

    while (1)
    {
        if (exit_nfc_thread)
        {
            printf("Quitting UpdateCycle thread...\n");
            pthread_exit(NULL);
        }
        // clear messageBuffer before read
        memset(messageBuffer, 0, sizeof(messageBuffer));

        // read the message from server
        retCode = ReadMessage(endpointFd, messageBuffer, sizeof(messageBuffer), identity);

        // if read failed, return from UpdateCyle
        if (retCode == -1)
        {
            return;
        }

        // check message type for client action status
        ParseJSONMessage(messageBuffer, flags, identity);

        if (flags[PUSH_DATA])
        {
            // update local copy of data
            printf("Fake Updated local copy\n");
            flags[PUSH_DATA] = 0;
        }

        if (flags[GET_DATA])
        {
            // push NFC ID
            char *message = PrepareJSONMessage();
            retCode = SendMessage(endpointFd, message, strlen(message), identity);
            if (retCode == -1)
            {
                free(message);
                return;
            }
            free(message);
            flags[GET_DATA] = 0;
        }
    }
}

int main(int argc, char *argv[])
{
    int retCode;
    char errorBuffer[ERRNO_MAX_SIZE];

    // handle SIGUSR1 signal to de-initialize NFC app
    HandleSignal(SIGUSR1,&CleanUp);

    pthread_t tid;

    sem_init(&semaphore, 0, 1);

    // prepare the logging file structure on evse.conf file parsed by server
    if (argc == 2)
    {
        logLevel = atoi(argv[1]);
        if (logLevel > NONE)
        {
            PrepareLoggingEnv(identity);
        }
    }

    // initialize local socket communication
    endpointFd = InitSocket(identity);
    if (endpointFd == -1)
    {
        CleanUp(RUNTIME_ISSUE);
        return endpointFd;
    }

    // start client handshake procedure
    retCode = SendIdentity(endpointFd, identity);
    if (retCode == -1)
    {
        CleanUp(RUNTIME_ISSUE);
        return retCode;
    }

    retCode = pthread_create(&tid, NULL, UpdateCycle, NULL);

    if (retCode)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                ((__LINE__)-4), __func__, errno, strerror(errno));
        LogEvent(identity, NFC_THREAD_CREATION_FAIL, errorBuffer, logFileDesc);
    }
    else
    {
        LogEvent(identity, NFC_THREAD_CREATION_OK, NULL, logFileDesc);
    }

    cmd_poll();
    exit_nfc_thread = true;
    pthread_join(tid, NULL);

    return 0;
}
