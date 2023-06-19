/******************************************************************************
 *
 *  Copyright 2015-2021, 2023 NXP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License")
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/


#include "../include/nfc_api.h"

nfc_tag_info_t g_TagInfo;
sem_t semaphore;

void *g_ThreadHandle = NULL;
void *g_devLock = NULL;
void *g_SnepClientLock = NULL;
void *g_HCELock = NULL;
eDevState g_DevState = eDevState_NONE;
eDevType g_Dev_Type = eDevType_NONE;
eSnepClientState g_SnepClientState = eSnepClientState_OFF;
eHCEState g_HCEState = eHCEState_NONE;
nfcTagCallback_t g_TagCB;
nfcHostCardEmulationCallback_t g_HceCB;
nfcSnepServerCallback_t g_SnepServerCB;
nfcSnepClientCallback_t g_SnepClientCB;
unsigned char *HCE_data = NULL;
unsigned int HCE_dataLenght = 0x00;
const unsigned char T4T_NDEF_EMU_APP_Select[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
const unsigned char T4T_NDEF_EMU_CC[] = {0x00, 0x0F, 0x20, 0x00, 0xFF, 0x00, 0xFF, 0x04, 0x06, 0xE1, 0x04, 0x00, 0xFF, 0x00, 0xFF};
const unsigned char T4T_NDEF_EMU_CC_Select[] = {0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03};
const unsigned char T4T_NDEF_EMU_NDEF_Select[] = {0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x04};
const unsigned char T4T_NDEF_EMU_Read[] = {0x00, 0xB0};
const unsigned char T4T_NDEF_EMU_OK[] = {0x90, 0x00};
const unsigned char T4T_NDEF_EMU_NOK[] = {0x6A, 0x82};
unsigned char *pT4T_NdefRecord = NULL;
unsigned short T4T_NdefRecord_size = 0;

T4T_NDEF_EMU_state_t eT4T_NDEF_EMU_State = Ready;
T4T_NDEF_EMU_Callback_t *pT4T_NDEF_EMU_PushCb = NULL;

#define NFC_DEBUG 0
#define NFCPRINT(...)        \
    if (NFC_DEBUG)           \
        printf(__VA_ARGS__); \
    else                     \
        ;

/********************************** HCE **********************************/
void T4T_NDEF_EMU_FillRsp(unsigned char *pRsp, unsigned short offset, unsigned char length)
{
    if (offset == 0)
    {
        pRsp[0] = (T4T_NdefRecord_size & 0xFF00) >> 8;
        pRsp[1] = (T4T_NdefRecord_size & 0x00FF);
        memcpy(&pRsp[2], &pT4T_NdefRecord[0], length - 2);
    }
    else if (offset == 1)
    {
        pRsp[0] = (T4T_NdefRecord_size & 0x00FF);
        memcpy(&pRsp[1], &pT4T_NdefRecord[0], length - 1);
    }
    else
    {
        memcpy(pRsp, &pT4T_NdefRecord[offset - 2], length);
    }
    /* Did we reached the end of NDEF record ?*/
    if ((offset + length) >= (T4T_NdefRecord_size + 2))
    {
        /* Notify application of the NDEF send */
        if (pT4T_NDEF_EMU_PushCb != NULL)
            pT4T_NDEF_EMU_PushCb(pT4T_NdefRecord, T4T_NdefRecord_size);
    }
}

void T4T_NDEF_EMU_SetRecord(unsigned char *pRecord, unsigned short Record_size, T4T_NDEF_EMU_Callback_t *cb)
{
    pT4T_NdefRecord = pRecord;
    T4T_NdefRecord_size = Record_size;
    pT4T_NDEF_EMU_PushCb = cb;
}

void T4T_NDEF_EMU_Reset(void)
{
    eT4T_NDEF_EMU_State = Ready;
}

void T4T_NDEF_EMU_Next(unsigned char *pCmd, unsigned short Cmd_size, unsigned char *pRsp, unsigned short *pRsp_size)
{
    unsigned char eStatus = 0x00;
    if (!memcmp(pCmd, T4T_NDEF_EMU_APP_Select, sizeof(T4T_NDEF_EMU_APP_Select)))
    {
        *pRsp_size = 0;
        eStatus = 0x01;
        eT4T_NDEF_EMU_State = NDEF_Application_Selected;
    }
    else if (!memcmp(pCmd, T4T_NDEF_EMU_CC_Select, sizeof(T4T_NDEF_EMU_CC_Select)))
    {
        if (eT4T_NDEF_EMU_State == NDEF_Application_Selected)
        {
            *pRsp_size = 0;
            eStatus = 0x01;
            eT4T_NDEF_EMU_State = CC_Selected;
        }
    }
    else if (!memcmp(pCmd, T4T_NDEF_EMU_NDEF_Select, sizeof(T4T_NDEF_EMU_NDEF_Select)))
    {
        *pRsp_size = 0;
        eStatus = 0x01;
        eT4T_NDEF_EMU_State = NDEF_Selected;
    }
    else if (!memcmp(pCmd, T4T_NDEF_EMU_Read, sizeof(T4T_NDEF_EMU_Read)))
    {
        if (eT4T_NDEF_EMU_State == CC_Selected)
        {
            memcpy(pRsp, T4T_NDEF_EMU_CC, sizeof(T4T_NDEF_EMU_CC));
            *pRsp_size = sizeof(T4T_NDEF_EMU_CC);
            eStatus = 0x01;
        }
        else if (eT4T_NDEF_EMU_State == NDEF_Selected)
        {
            unsigned short offset = (pCmd[2] << 8) + pCmd[3];
            unsigned char length = pCmd[4];
            if (length <= (T4T_NdefRecord_size + offset + 2))
            {
                T4T_NDEF_EMU_FillRsp(pRsp, offset, length);
                *pRsp_size = length;
                eStatus = 0x01;
            }
        }
    }
    if (eStatus == 0x01)
    {
        memcpy(&pRsp[*pRsp_size], T4T_NDEF_EMU_OK, sizeof(T4T_NDEF_EMU_OK));
        *pRsp_size += sizeof(T4T_NDEF_EMU_OK);
    }
    else
    {
        memcpy(pRsp, T4T_NDEF_EMU_NOK, sizeof(T4T_NDEF_EMU_NOK));
        *pRsp_size = sizeof(T4T_NDEF_EMU_NOK);
        T4T_NDEF_EMU_Reset();
    }
}

/********************************** CallBack **********************************/
void onDataReceived(unsigned char *data, unsigned int data_length)
{
    framework_LockMutex(g_HCELock);

    HCE_dataLenght = data_length;
    HCE_data = malloc(HCE_dataLenght * sizeof(unsigned char));
    memcpy(HCE_data, data, data_length);

    if (eHCEState_NONE == g_HCEState)
    {
        g_HCEState = eHCEState_DATA_RECEIVED;
    }
    else if (eHCEState_WAIT_DATA == g_HCEState)
    {
        g_HCEState = eHCEState_DATA_RECEIVED;
        framework_NotifyMutex(g_HCELock, 0);
    }

    framework_UnlockMutex(g_HCELock);
}

void onHostCardEmulationActivated(unsigned char mode)
{
    framework_LockMutex(g_devLock);

    T4T_NDEF_EMU_Reset();

    if (eDevState_WAIT_ARRIVAL == g_DevState)
    {
        NFCPRINT("\tNFC Reader Found, mode=0x%.2x\n\n", mode);
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_READER;
        framework_NotifyMutex(g_devLock, 0);
    }
    else if (eDevState_WAIT_DEPARTURE == g_DevState)
    {
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_READER;
        framework_NotifyMutex(g_devLock, 0);
    }
    else if (eDevState_EXIT == g_DevState)
    {
        g_DevState = eDevState_DEPARTED;
        g_Dev_Type = eDevType_NONE;
        framework_NotifyMutex(g_devLock, 0);
    }
    else
    {
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_READER;
    }
    framework_UnlockMutex(g_devLock);
}

void onHostCardEmulationDeactivated()
{
    framework_LockMutex(g_devLock);

    if (eDevState_WAIT_DEPARTURE == g_DevState)
    {
        NFCPRINT("\tNFC Reader Lost\n\n");
        g_DevState = eDevState_DEPARTED;
        g_Dev_Type = eDevType_NONE;
        framework_NotifyMutex(g_devLock, 0);
    }
    else if (eDevState_PRESENT == g_DevState)
    {
        NFCPRINT("\tNFC Reader Lost\n\n");
        g_DevState = eDevState_DEPARTED;
        g_Dev_Type = eDevType_NONE;
    }
    else if (eDevState_WAIT_ARRIVAL == g_DevState)
    {
    }
    else if (eDevState_EXIT == g_DevState)
    {
    }
    else
    {
        g_DevState = eDevState_DEPARTED;
        g_Dev_Type = eDevType_NONE;
    }
    framework_UnlockMutex(g_devLock);

    framework_LockMutex(g_HCELock);
    if (eHCEState_WAIT_DATA == g_HCEState)
    {
        g_HCEState = eHCEState_NONE;
        framework_NotifyMutex(g_HCELock, 0x00);
    }
    else if (eHCEState_EXIT == g_HCEState)
    {
    }
    else
    {
        g_HCEState = eHCEState_NONE;
    }
    framework_UnlockMutex(g_HCELock);
}

void onTagArrival(nfc_tag_info_t *pTagInfo)
{
    framework_LockMutex(g_devLock);

    if (eDevState_WAIT_ARRIVAL == g_DevState)
    {
        NFCPRINT("\tNFC Tag Found\n\n");
        memcpy(&g_TagInfo, pTagInfo, sizeof(nfc_tag_info_t));
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_TAG;
        framework_NotifyMutex(g_devLock, 0);
    }
    else if (eDevState_WAIT_DEPARTURE == g_DevState)
    {
        memcpy(&g_TagInfo, pTagInfo, sizeof(nfc_tag_info_t));
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_TAG;
        framework_NotifyMutex(g_devLock, 0);
    }
    else if (eDevState_EXIT == g_DevState)
    {
        g_DevState = eDevState_DEPARTED;
        g_Dev_Type = eDevType_NONE;
        framework_NotifyMutex(g_devLock, 0);
    }
    else
    {
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_TAG;
    }
    framework_UnlockMutex(g_devLock);
}

void onTagDeparture(void)
{
    framework_LockMutex(g_devLock);

    if (eDevState_WAIT_DEPARTURE == g_DevState)
    {
        NFCPRINT("\tNFC Tag Lost\n\n");
        g_DevState = eDevState_DEPARTED;
        g_Dev_Type = eDevType_NONE;
        framework_NotifyMutex(g_devLock, 0);
    }
    else if (eDevState_WAIT_ARRIVAL == g_DevState)
    {
    }
    else if (eDevState_EXIT == g_DevState)
    {
    }
    else
    {
        g_DevState = eDevState_DEPARTED;
        g_Dev_Type = eDevType_NONE;
    }
    framework_UnlockMutex(g_devLock);
}

void onDeviceArrival(void)
{
    framework_LockMutex(g_devLock);

    switch (g_DevState)
    {
    case eDevState_WAIT_DEPARTURE:
    {
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_P2P;
        framework_NotifyMutex(g_devLock, 0);
    }
    break;
    case eDevState_EXIT:
    {
        g_Dev_Type = eDevType_P2P;
    }
    break;
    case eDevState_NONE:
    {
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_P2P;
    }
    break;
    case eDevState_WAIT_ARRIVAL:
    {
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_P2P;
        framework_NotifyMutex(g_devLock, 0);
    }
    break;
    case eDevState_PRESENT:
    {
        g_Dev_Type = eDevType_P2P;
    }
    break;
    case eDevState_DEPARTED:
    {
        g_Dev_Type = eDevType_P2P;
        g_DevState = eDevState_PRESENT;
    }
    break;
    }

    framework_UnlockMutex(g_devLock);
}

void onDeviceDeparture(void)
{
    framework_LockMutex(g_devLock);

    switch (g_DevState)
    {
    case eDevState_WAIT_DEPARTURE:
    {
        g_DevState = eDevState_DEPARTED;
        g_Dev_Type = eDevType_NONE;
        framework_NotifyMutex(g_devLock, 0);
    }
    break;
    case eDevState_EXIT:
    {
        g_Dev_Type = eDevType_NONE;
    }
    break;
    case eDevState_NONE:
    {
        g_Dev_Type = eDevType_NONE;
    }
    break;
    case eDevState_WAIT_ARRIVAL:
    {
        g_Dev_Type = eDevType_NONE;
    }
    break;
    case eDevState_PRESENT:
    {
        g_Dev_Type = eDevType_NONE;
        g_DevState = eDevState_DEPARTED;
    }
    break;
    case eDevState_DEPARTED:
    {
        g_Dev_Type = eDevType_NONE;
    }
    break;
    }
    framework_UnlockMutex(g_devLock);

    framework_LockMutex(g_SnepClientLock);

    switch (g_SnepClientState)
    {
    case eSnepClientState_WAIT_OFF:
    {
        g_SnepClientState = eSnepClientState_OFF;
        framework_NotifyMutex(g_SnepClientLock, 0);
    }
    break;
    case eSnepClientState_OFF:
    {
    }
    break;
    case eSnepClientState_WAIT_READY:
    {
        g_SnepClientState = eSnepClientState_OFF;
        framework_NotifyMutex(g_SnepClientLock, 0);
    }
    break;
    case eSnepClientState_READY:
    {
        g_SnepClientState = eSnepClientState_OFF;
    }
    break;
    case eSnepClientState_EXIT:
    {
    }
    break;
    }

    framework_UnlockMutex(g_SnepClientLock);
}

void onMessageReceived(unsigned char *message, unsigned int length)
{
    unsigned int i = 0x00;
    NFCPRINT("\n\t\tNDEF Message Received : \n");
    PrintNDEFContent(NULL, NULL, message, length);
}

void onSnepClientReady()
{
    framework_LockMutex(g_devLock);

    switch (g_DevState)
    {
    case eDevState_WAIT_DEPARTURE:
    {
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_P2P;
        framework_NotifyMutex(g_devLock, 0);
    }
    break;
    case eDevState_EXIT:
    {
        g_Dev_Type = eDevType_P2P;
    }
    break;
    case eDevState_NONE:
    {
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_P2P;
    }
    break;
    case eDevState_WAIT_ARRIVAL:
    {
        g_DevState = eDevState_PRESENT;
        g_Dev_Type = eDevType_P2P;
        framework_NotifyMutex(g_devLock, 0);
    }
    break;
    case eDevState_PRESENT:
    {
        g_Dev_Type = eDevType_P2P;
    }
    break;
    case eDevState_DEPARTED:
    {
        g_Dev_Type = eDevType_P2P;
        g_DevState = eDevState_PRESENT;
    }
    break;
    }
    framework_UnlockMutex(g_devLock);

    framework_LockMutex(g_SnepClientLock);

    switch (g_SnepClientState)
    {
    case eSnepClientState_WAIT_OFF:
    {
        g_SnepClientState = eSnepClientState_READY;
        framework_NotifyMutex(g_SnepClientLock, 0);
    }
    break;
    case eSnepClientState_OFF:
    {
        g_SnepClientState = eSnepClientState_READY;
    }
    break;
    case eSnepClientState_WAIT_READY:
    {
        g_SnepClientState = eSnepClientState_READY;
        framework_NotifyMutex(g_SnepClientLock, 0);
    }
    break;
    case eSnepClientState_READY:
    {
    }
    break;
    case eSnepClientState_EXIT:
    {
    }
    break;
    }

    framework_UnlockMutex(g_SnepClientLock);
}

void onSnepClientClosed()
{
    framework_LockMutex(g_devLock);

    switch (g_DevState)
    {
    case eDevState_WAIT_DEPARTURE:
    {
        g_DevState = eDevState_DEPARTED;
        g_Dev_Type = eDevType_NONE;
        framework_NotifyMutex(g_devLock, 0);
    }
    break;
    case eDevState_EXIT:
    {
        g_Dev_Type = eDevType_NONE;
    }
    break;
    case eDevState_NONE:
    {
        g_Dev_Type = eDevType_NONE;
    }
    break;
    case eDevState_WAIT_ARRIVAL:
    {
        g_Dev_Type = eDevType_NONE;
    }
    break;
    case eDevState_PRESENT:
    {
        g_Dev_Type = eDevType_NONE;
        g_DevState = eDevState_DEPARTED;
    }
    break;
    case eDevState_DEPARTED:
    {
        g_Dev_Type = eDevType_NONE;
    }
    break;
    }
    framework_UnlockMutex(g_devLock);

    framework_LockMutex(g_SnepClientLock);

    switch (g_SnepClientState)
    {
    case eSnepClientState_WAIT_OFF:
    {
        g_SnepClientState = eSnepClientState_OFF;
        framework_NotifyMutex(g_SnepClientLock, 0);
    }
    break;
    case eSnepClientState_OFF:
    {
    }
    break;
    case eSnepClientState_WAIT_READY:
    {
        g_SnepClientState = eSnepClientState_OFF;
        framework_NotifyMutex(g_SnepClientLock, 0);
    }
    break;
    case eSnepClientState_READY:
    {
        g_SnepClientState = eSnepClientState_OFF;
    }
    break;
    case eSnepClientState_EXIT:
    {
    }
    break;
    }

    framework_UnlockMutex(g_SnepClientLock);
}

int InitMode(int tag, int p2p, int hce)
{
    int res = 0x00;

    InitializeLogLevel();
    g_TagCB.onTagArrival = onTagArrival;
    g_TagCB.onTagDeparture = onTagDeparture;

    g_SnepServerCB.onDeviceArrival = onDeviceArrival;
    g_SnepServerCB.onDeviceDeparture = onDeviceDeparture;
    g_SnepServerCB.onMessageReceived = onMessageReceived;

    g_SnepClientCB.onDeviceArrival = onSnepClientReady;
    g_SnepClientCB.onDeviceDeparture = onSnepClientClosed;

    g_HceCB.onDataReceived = onDataReceived;
    g_HceCB.onHostCardEmulationActivated = onHostCardEmulationActivated;
    g_HceCB.onHostCardEmulationDeactivated = onHostCardEmulationDeactivated;

    if (0x00 == res)
    {
        res = doInitialize();
        if (0x00 != res)
        {
            NFCPRINT("NfcService Init Failed\n");
        }
    }

    if (0x00 == res)
    {
        if (0x01 == tag)
        {
            registerTagCallback(&g_TagCB);
        }
#ifdef SNEP_ENABLED
        if (0x01 == p2p)
        {
            res = nfcSnep_registerClientCallback(&g_SnepClientCB);
            if (0x00 != res)
            {
                NFCPRINT("SNEP Client Register Callback Failed\n");
            }
        }
#endif
    }

    if (0x00 == res && 0x01 == hce)
    {
        nfcHce_registerHceCallback(&g_HceCB);
    }
    if (0x00 == res)
    {
        doEnableDiscovery(DEFAULT_NFA_TECH_MASK, 0x00, hce, 0);
        if (0x01 == p2p)
        {
#ifdef SNEP_ENABLED
            res = nfcSnep_startServer(&g_SnepServerCB);
            if (0x00 != res)
            {
                NFCPRINT("Start SNEP Server Failed\n");
            }
#endif
        }
    }

    return res;
}

void DeinitPollMode()
{
    nfcSnep_stopServer();
    disableDiscovery();

    nfcSnep_deregisterClientCallback();
    deregisterTagCallback();

    nfcHce_deregisterHceCallback();

    return;
}

int SnepPush(unsigned char *msgToPush, unsigned int len)
{
    int res = 0x00;

    framework_LockMutex(g_devLock);
    framework_LockMutex(g_SnepClientLock);

    if (eSnepClientState_READY != g_SnepClientState && eSnepClientState_EXIT != g_SnepClientState && eDevState_PRESENT == g_DevState)
    {
        framework_UnlockMutex(g_devLock);
        g_SnepClientState = eSnepClientState_WAIT_READY;
        framework_WaitMutex(g_SnepClientLock, 0);
    }
    else
    {
        framework_UnlockMutex(g_devLock);
    }

    if (eSnepClientState_READY == g_SnepClientState)
    {
        framework_UnlockMutex(g_SnepClientLock);
        res = nfcSnep_putMessage(msgToPush, len);
        if (0x00 != res)
        {
            NFCPRINT("\t\tPush Failed\n");
        }
        else
        {
            NFCPRINT("\t\tPush successful\n");
        }
    }
    else
    {
        framework_UnlockMutex(g_SnepClientLock);
    }

    return res;
}

int WriteTag(nfc_tag_info_t TagInfo, unsigned char *msgToPush, unsigned int len)
{
    int res = 0x00;

    res = nfcTag_writeNdef(TagInfo.handle, msgToPush, len);
    if (0x00 != res)
    {
        res = 0xFF;
    }
    else
    {
        res = 0x00;
    }
    return res;
}

void PrintfNDEFInfo(ndef_info_t pNDEFinfo)
{
    if (0x01 == pNDEFinfo.is_ndef)
    {
        NFCPRINT("\t\tRecord Found :\n");
        NFCPRINT("\t\t\t\tNDEF Content Max size :     '%d bytes'\n", pNDEFinfo.max_ndef_length);
        NFCPRINT("\t\t\t\tNDEF Actual Content size :     '%d bytes'\n", pNDEFinfo.current_ndef_length);
        if (0x01 == pNDEFinfo.is_writable)
        {
            NFCPRINT("\t\t\t\tReadOnly :                      'FALSE'\n");
        }
        else
        {
            NFCPRINT("\t\t\t\tReadOnly :                         'TRUE'\n");
        }
    }
    else
    {
        NFCPRINT("\t\tNo Record found\n");
    }
}

void open_uri(const char *uri)
{
    char *temp = malloc(strlen("xdg-open ") + strlen(uri) + 1);
    if (temp != NULL)
    {
        strcpy(temp, "xdg-open ");
        strcat(temp, uri);
        strcat(temp, "&");
        NFCPRINT("\t\t- Opening URI in web browser ...\n");
        system(temp);
        free(temp);
    }
}

void PrintNDEFContent(nfc_tag_info_t *TagInfo, ndef_info_t *NDEFinfo, unsigned char *ndefRaw, unsigned int ndefRawLen)
{
    unsigned char *NDEFContent = NULL;
    nfc_friendly_type_t lNDEFType = NDEF_FRIENDLY_TYPE_OTHER;
    unsigned int res = 0x00;
    unsigned int i = 0x00;
    unsigned int langCode_len;
    char *LanguageCode = NULL;
    char *TextContent = NULL;
    char *URLContent = NULL;
    nfc_handover_select_t HandoverSelectContent;
    nfc_handover_request_t HandoverRequestContent;
    if (NULL != NDEFinfo)
    {
        ndefRawLen = NDEFinfo->current_ndef_length;
        NDEFContent = malloc(ndefRawLen * sizeof(unsigned char));
        memset(NDEFContent, 0x0, ndefRawLen * sizeof(unsigned char));
        res = nfcTag_readNdef(TagInfo->handle, NDEFContent, ndefRawLen, &lNDEFType);
    }
    else if (NULL != ndefRaw && 0x00 != ndefRawLen)
    {
        NDEFContent = malloc(ndefRawLen * sizeof(unsigned char));
        memcpy(NDEFContent, ndefRaw, ndefRawLen);
        res = ndefRawLen;
        if ((NDEFContent[0] & 0x7) == NDEF_TNF_WELLKNOWN && 0x55 == NDEFContent[3])
        {
            lNDEFType = NDEF_FRIENDLY_TYPE_URL;
        }
        if ((NDEFContent[0] & 0x7) == NDEF_TNF_WELLKNOWN && 0x54 == NDEFContent[3])
        {
            lNDEFType = NDEF_FRIENDLY_TYPE_TEXT;
        }
    }
    else
    {
        NFCPRINT("\t\t\t\tError : Invalid Parameters\n");
    }

    if (res != ndefRawLen)
    {
        NFCPRINT("\t\t\t\tRead NDEF Content Failed\n");
    }
    else
    {
        switch (lNDEFType)
        {
        case NDEF_FRIENDLY_TYPE_TEXT:
        {
            TextContent = malloc(res * sizeof(char));
            langCode_len = ndef_readLanguageCode(NDEFContent, res, TextContent, res);
            if (0x00 <= langCode_len)
            {
                LanguageCode = malloc((langCode_len + 1) * sizeof(char));
                memcpy(LanguageCode, TextContent, langCode_len);
                LanguageCode[langCode_len] = '\0'; /* Add extra character for proper display */
                res = ndef_readText(NDEFContent, res, TextContent, res);
                if (0x00 <= res)
                {
                    TextContent[res] = '\0'; /* Add extra character for proper display */
                    NFCPRINT("\t\t\t\tType :                 'Text'\n");
                    NFCPRINT("\t\t\t\tLang :                 '%s'\n", LanguageCode);
                    NFCPRINT("\t\t\t\tText :                 '%s'\n\n", TextContent);
                }
                else
                {
                    NFCPRINT("\t\t\t\tRead NDEF Text Error\n");
                }
            }
            if (NULL != TextContent)
            {
                free(TextContent);
                TextContent = NULL;
            }
        }
        break;
        case NDEF_FRIENDLY_TYPE_URL:
        {
            /*NOTE : + 27 = Max prefix lenght*/
            URLContent = malloc(res * sizeof(unsigned char) + 27);
            memset(URLContent, 0x00, res * sizeof(unsigned char) + 27);
            res = ndef_readUrl(NDEFContent, res, URLContent, res + 27);
            if (0x00 <= res)
            {
                NFCPRINT("\t\t\t\tType :                 'URI'\n");
                NFCPRINT("\t\t\t\t URI :                 '%s'\n\n", URLContent);
                /*NOTE: open url in browser*/
                /*open_uri(URLContent);*/
            }
            else
            {
                NFCPRINT("                Read NDEF URL Error\n");
            }
            if (NULL != URLContent)
            {
                free(URLContent);
                URLContent = NULL;
            }
        }
        break;
        case NDEF_FRIENDLY_TYPE_HS:
        {
            res = ndef_readHandoverSelectInfo(NDEFContent, res, &HandoverSelectContent);
            if (0x00 <= res)
            {
                NFCPRINT("\n\t\tHandover Select : \n");

                NFCPRINT("\t\tBluetooth : \n\t\t\t\tPower state : ");
                switch (HandoverSelectContent.bluetooth.power_state)
                {
                case HANDOVER_CPS_INACTIVE:
                {
                    NFCPRINT(" 'Inactive'\n");
                }
                break;
                case HANDOVER_CPS_ACTIVE:
                {
                    NFCPRINT(" 'Active'\n");
                }
                break;
                case HANDOVER_CPS_ACTIVATING:
                {
                    NFCPRINT(" 'Activating'\n");
                }
                break;
                case HANDOVER_CPS_UNKNOWN:
                {
                    NFCPRINT(" 'Unknown'\n");
                }
                break;
                default:
                {
                    NFCPRINT(" 'Unknown'\n");
                }
                break;
                }
                if (HANDOVER_TYPE_BT == HandoverSelectContent.bluetooth.type)
                {
                    NFCPRINT("\t\t\t\tType :         'BT'\n");
                }
                else if (HANDOVER_TYPE_BLE == HandoverSelectContent.bluetooth.type)
                {
                    NFCPRINT("\t\t\t\tType :         'BLE'\n");
                }
                else
                {
                    NFCPRINT("\t\t\t\tType :            'Unknown'\n");
                }
                NFCPRINT("\t\t\t\tAddress :      '");
                for (i = 0x00; i < 6; i++)
                {
                    NFCPRINT("%02X ", HandoverSelectContent.bluetooth.address[i]);
                }
                NFCPRINT("'\n\t\t\t\tDevice Name :  '");
                for (i = 0x00; i < HandoverSelectContent.bluetooth.device_name_length; i++)
                {
                    NFCPRINT("%c ", HandoverSelectContent.bluetooth.device_name[i]);
                }
                NFCPRINT("'\n\t\t\t\tNDEF Record :     \n\t\t\t\t");
                for (i = 0x01; i < HandoverSelectContent.bluetooth.ndef_length + 1; i++)
                {
                    NFCPRINT("%02X ", HandoverSelectContent.bluetooth.ndef[i]);
                    if (i % 8 == 0)
                    {
                        NFCPRINT("\n\t\t\t\t");
                    }
                }
                NFCPRINT("\n\t\tWIFI : \n\t\t\t\tPower state : ");
                switch (HandoverSelectContent.wifi.power_state)
                {
                case HANDOVER_CPS_INACTIVE:
                {
                    NFCPRINT(" 'Inactive'\n");
                }
                break;
                case HANDOVER_CPS_ACTIVE:
                {
                    NFCPRINT(" 'Active'\n");
                }
                break;
                case HANDOVER_CPS_ACTIVATING:
                {
                    NFCPRINT(" 'Activating'\n");
                }
                break;
                case HANDOVER_CPS_UNKNOWN:
                {
                    NFCPRINT(" 'Unknown'\n");
                }
                break;
                default:
                {
                    NFCPRINT(" 'Unknown'\n");
                }
                break;
                }

                NFCPRINT("\t\t\t\tSSID :         '");
                for (i = 0x01; i < HandoverSelectContent.wifi.ssid_length + 1; i++)
                {
                    NFCPRINT("%02X ", HandoverSelectContent.wifi.ssid[i]);
                    if (i % 30 == 0)
                    {
                        NFCPRINT("\n");
                    }
                }
                NFCPRINT("'\n\t\t\t\tKey :          '");
                for (i = 0x01; i < HandoverSelectContent.wifi.key_length + 1; i++)
                {
                    NFCPRINT("%02X ", HandoverSelectContent.wifi.key[i]);
                    if (i % 30 == 0)
                    {
                        NFCPRINT("\n");
                    }
                }
                NFCPRINT("'\n\t\t\t\tNDEF Record : \n");
                for (i = 0x01; i < HandoverSelectContent.wifi.ndef_length + 1; i++)
                {
                    NFCPRINT("%02X ", HandoverSelectContent.wifi.ndef[i]);
                    if (i % 30 == 0)
                    {
                        NFCPRINT("\n");
                    }
                }
                NFCPRINT("\n");
            }
            else
            {
                NFCPRINT("\n\t\tRead NDEF Handover Select Failed\n");
            }
        }
        break;
        case NDEF_FRIENDLY_TYPE_HR:
        {
            res = ndef_readHandoverRequestInfo(NDEFContent, res, &HandoverRequestContent);
            if (0x00 <= res)
            {
                NFCPRINT("\n\t\tHandover Request : \n");
                NFCPRINT("\t\tBluetooth : \n\t\t\t\tPower state : ");
                switch (HandoverRequestContent.bluetooth.power_state)
                {
                case HANDOVER_CPS_INACTIVE:
                {
                    NFCPRINT(" 'Inactive'\n");
                }
                break;
                case HANDOVER_CPS_ACTIVE:
                {
                    NFCPRINT(" 'Active'\n");
                }
                break;
                case HANDOVER_CPS_ACTIVATING:
                {
                    NFCPRINT(" 'Activating'\n");
                }
                break;
                case HANDOVER_CPS_UNKNOWN:
                {
                    NFCPRINT(" 'Unknown'\n");
                }
                break;
                default:
                {
                    NFCPRINT(" 'Unknown'\n");
                }
                break;
                }
                if (HANDOVER_TYPE_BT == HandoverRequestContent.bluetooth.type)
                {
                    NFCPRINT("\t\t\t\tType :         'BT'\n");
                }
                else if (HANDOVER_TYPE_BLE == HandoverRequestContent.bluetooth.type)
                {
                    NFCPRINT("\t\t\t\tType :         'BLE'\n");
                }
                else
                {
                    NFCPRINT("\t\t\t\tType :            'Unknown'\n");
                }
                NFCPRINT("\t\t\t\tAddress :      '");
                for (i = 0x00; i < 6; i++)
                {
                    NFCPRINT("%02X ", HandoverRequestContent.bluetooth.address[i]);
                }
                NFCPRINT("'\n\t\t\t\tDevice Name :  '");
                for (i = 0x00; i < HandoverRequestContent.bluetooth.device_name_length; i++)
                {
                    NFCPRINT("%c ", HandoverRequestContent.bluetooth.device_name[i]);
                }
                NFCPRINT("'\n\t\t\t\tNDEF Record :     \n\t\t\t\t");
                for (i = 0x01; i < HandoverRequestContent.bluetooth.ndef_length + 1; i++)
                {
                    NFCPRINT("%02X ", HandoverRequestContent.bluetooth.ndef[i]);
                    if (i % 8 == 0)
                    {
                        NFCPRINT("\n\t\t\t\t");
                    }
                }
                NFCPRINT("\n\t\t\t\tWIFI :         'Has WIFI Request : %X '", HandoverRequestContent.wifi.has_wifi);
                NFCPRINT("\n\t\t\t\tNDEF Record :     \n\t\t\t\t");
                for (i = 0x01; i < HandoverRequestContent.wifi.ndef_length + 1; i++)
                {
                    NFCPRINT("%02X ", HandoverRequestContent.wifi.ndef[i]);
                    if (i % 8 == 0)
                    {
                        NFCPRINT("\n\t\t\t\t");
                    }
                }
                NFCPRINT("\n");
            }
            else
            {
                NFCPRINT("\n\t\tRead NDEF Handover Request Failed\n");
            }
        }
        break;
        case NDEF_FRIENDLY_TYPE_OTHER:
        {
            switch (NDEFContent[0] & 0x7)
            {
            case NDEF_TNF_EMPTY:
            {
                NFCPRINT("\n\t\tTNF Empty\n");
            }
            break;
            case NDEF_TNF_WELLKNOWN:
            {
                NFCPRINT("\n\t\tTNF Well Known\n");
            }
            break;
            case NDEF_TNF_MEDIA:
            {
                NFCPRINT("\n\t\tTNF Media\n\n");
                NFCPRINT("\t\t\tType : ");
                for (i = 0x00; i < NDEFContent[1]; i++)
                {
                    NFCPRINT("%c", NDEFContent[3 + i]);
                }
                NFCPRINT("\n\t\t\tData : ");
                for (i = 0x00; i < NDEFContent[2]; i++)
                {
                    NFCPRINT("%c", NDEFContent[3 + NDEFContent[1] + i]);
                    if ('\n' == NDEFContent[3 + NDEFContent[1] + i])
                    {
                        NFCPRINT("\t\t\t");
                    }
                }
                NFCPRINT("\n");
            }
            break;
            case NDEF_TNF_URI:
            {
                NFCPRINT("\n\t\tTNF URI\n");
            }
            break;
            case NDEF_TNF_EXT:
            {
                NFCPRINT("\n\t\tTNF External\n\n");
                NFCPRINT("\t\t\tType : ");
                for (i = 0x00; i < NDEFContent[1]; i++)
                {
                    NFCPRINT("%c", NDEFContent[3 + i]);
                }
                NFCPRINT("\n\t\t\tData : ");
                for (i = 0x00; i < NDEFContent[2]; i++)
                {
                    NFCPRINT("%c", NDEFContent[3 + NDEFContent[1] + i]);
                    if ('\n' == NDEFContent[3 + NDEFContent[1] + i])
                    {
                        NFCPRINT("\t\t\t");
                    }
                }
                NFCPRINT("\n");
            }
            break;
            case NDEF_TNF_UNKNOWN:
            {
                NFCPRINT("\n\t\tTNF Unknown\n");
            }
            break;
            case NDEF_TNF_UNCHANGED:
            {
                NFCPRINT("\n\t\tTNF Unchanged\n");
            }
            break;
            default:
            {
                NFCPRINT("\n\t\tTNF Other\n");
            }
            break;
            }
        }
        break;
        default:
        {
        }
        break;
        }
        NFCPRINT("\n\t\t%d bytes of NDEF data received :\n\t\t", ndefRawLen);
        for (i = 0x00; i < ndefRawLen; i++)
        {
            NFCPRINT("%02X ", NDEFContent[i]);
            if (i % 30 == 0 && 0x00 != i)
            {
                NFCPRINT("\n\t\t");
            }
        }
        NFCPRINT("\n\n");
    }

    if (NULL != NDEFContent)
    {
        free(NDEFContent);
        NDEFContent = NULL;
    }
}

/* mode=1 => poll, mode=2 => push, mode=3 => write, mode=4 => HCE */

int WaitDeviceArrival(int mode, unsigned char *msgToSend, unsigned int len)
{
    int res = 0x00;
    unsigned int i = 0x00;
    int block = 0x01;
    unsigned char key[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ndef_info_t NDEFinfo;
    eDevType DevTypeBck = eDevType_NONE;
    unsigned char MifareAuthCmd[] = {0x60U, 0x00 /*block*/, 0x02, 0x02, 0x02, 0x02, 0x00 /*key*/, 0x00 /*key*/, 0x00 /*key*/, 0x00 /*key*/, 0x00 /*key*/, 0x00 /*key*/};
    unsigned char MifareAuthResp[255];
    unsigned char MifareReadCmd[] = {0x30U, /*block*/ 0x00};
    unsigned char MifareWriteCmd[] = {0xA0U, /*block*/ 0x00, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55};
    unsigned char MifareResp[255];

    unsigned char HCEReponse[255];
    short unsigned int HCEResponseLen = 0x00;
    int tag_count = 0;
    int num_tags = 0;

    nfc_tag_info_t TagInfo;

    MifareAuthCmd[1] = block;
    memcpy(&MifareAuthCmd[6], key, 6);
    MifareReadCmd[1] = block;
    MifareWriteCmd[1] = block;

    do
    {
        framework_LockMutex(g_devLock);
        if (eDevState_EXIT == g_DevState)
        {
            framework_UnlockMutex(g_devLock);
            break;
        }

        else if (eDevState_PRESENT != g_DevState)
        {
            if (tag_count == 0)
                NFCPRINT("Waiting for a Tag/Device...\n\n");
            g_DevState = eDevState_WAIT_ARRIVAL;
            framework_WaitMutex(g_devLock, 0);
        }

        if (eDevState_EXIT == g_DevState)
        {
            framework_UnlockMutex(g_devLock);
            break;
        }

        if (eDevState_PRESENT == g_DevState)
        {
            DevTypeBck = g_Dev_Type;
            if (eDevType_TAG == g_Dev_Type)
            {
                memcpy(&TagInfo, &g_TagInfo, sizeof(nfc_tag_info_t));
                framework_UnlockMutex(g_devLock);
                NFCPRINT("        Type : ");
                switch (TagInfo.technology)
                {
                case TARGET_TYPE_UNKNOWN:
                {
                    NFCPRINT("        'Type Unknown'\n");
                }
                break;
                case TARGET_TYPE_ISO14443_3A:
                {
                    NFCPRINT("        'Type A'\n");
                }
                break;
                case TARGET_TYPE_ISO14443_3B:
                {
                    NFCPRINT("        'Type 4B'\n");
                }
                break;
                case TARGET_TYPE_ISO14443_4:
                {
                    NFCPRINT("        'Type 4A'\n");
                }
                break;
                case TARGET_TYPE_FELICA:
                {
                    NFCPRINT("        'Type F'\n");
                }
                break;
                case TARGET_TYPE_ISO15693:
                {
                    NFCPRINT("        'Type V'\n");
                }
                break;
                case TARGET_TYPE_NDEF:
                {
                    NFCPRINT("        'Type NDEF'\n");
                }
                break;
                case TARGET_TYPE_NDEF_FORMATABLE:
                {
                    NFCPRINT("        'Type Formatable'\n");
                }
                break;
                case TARGET_TYPE_MIFARE_CLASSIC:
                {
                    NFCPRINT("        'Type A - Mifare Classic'\n");
                }
                break;
                case TARGET_TYPE_MIFARE_UL:
                {
                    NFCPRINT("        'Type A - Mifare Ul'\n");
                }
                break;
                case TARGET_TYPE_KOVIO_BARCODE:
                {
                    NFCPRINT("        'Type A - Kovio Barcode'\n");
                }
                break;
                case TARGET_TYPE_ISO14443_3A_3B:
                {
                    NFCPRINT("        'Type A/B'\n");
                }
                break;
                default:
                {
                    NFCPRINT("        'Type %d (Unknown or not supported)'\n", TagInfo.technology);
                }
                break;
                }
                /*32 is max UID len (Kovio tags)*/
                if ((0x00 != TagInfo.uid_length) && (32 >= TagInfo.uid_length))
                {
                    if (4 == TagInfo.uid_length || 7 == TagInfo.uid_length || 10 == TagInfo.uid_length)
                    {
                        NFCPRINT("        NFCID1 :    \t'");
                    }
                    else if (8 == TagInfo.uid_length)
                    {
                        NFCPRINT("        NFCID2 :    \t'");
                    }
                    else
                    {
                        NFCPRINT("        UID :       \t'");
                    }

                    sem_wait(&semaphore);
                    for (i = 0x00; i < TagInfo.uid_length; i++)
                    {
                        NFCPRINT("%02X ", (unsigned char)TagInfo.uid[i]);
                        sprintf(&g_TagInfo.uid[3 * i], " %02X", TagInfo.uid[i]);
                    }
                    sem_post(&semaphore);

                    NFCPRINT("'\n");
                }
                res = nfcTag_isNdef(TagInfo.handle, &NDEFinfo);
                if (0x01 == res)
                {
                    PrintfNDEFInfo(NDEFinfo);
                    PrintNDEFContent(&TagInfo, &NDEFinfo, NULL, 0x00);
                }
                else
                {
                    NFCPRINT("\t\tNDEF Content : NO, mode=%d, tech=%d\n", mode, TagInfo.technology);

                    if (0x03 == mode)
                    {
                        NFCPRINT("\n\tFormating tag to NDEF prior to write ...\n");
                        if (nfcTag_isFormatable(TagInfo.handle))
                        {
                            if (nfcTag_formatTag(TagInfo.handle) == 0x00)
                            {
                                NFCPRINT("\tTag formating succeed\n");
                            }
                            else
                            {
                                NFCPRINT("\tTag formating failed\n");
                            }
                        }
                        else
                        {
                            NFCPRINT("\tTag is not formatable\n");
                        }
                    }
                    else if (TARGET_TYPE_MIFARE_CLASSIC == TagInfo.technology)
                    {
                        memset(MifareAuthResp, 0x00, 255);
                        memset(MifareResp, 0x00, 255);
                        res = nfcTag_transceive(TagInfo.handle, MifareAuthCmd, 12, MifareAuthResp, 255, 500);
                        if (0x00 == res)
                        {
                            NFCPRINT("\n\t\tRAW Tag transceive failed\n");
                        }
                        else
                        {
                            NFCPRINT("\n\t\tMifare Authenticate command sent\n\t\tResponse : \n\t\t");
                            for (i = 0x00; i < (unsigned int)res; i++)
                            {
                                NFCPRINT("%02X ", MifareAuthResp[i]);
                            }
                            NFCPRINT("\n");

                            res = nfcTag_transceive(TagInfo.handle, MifareReadCmd, 2, MifareResp, 255, 500);
                            if (0x00 == res)
                            {
                                NFCPRINT("\n\t\tRAW Tag transceive failed\n");
                            }
                            else
                            {
                                NFCPRINT("\n\t\tMifare Read command sent\n\t\tResponse : \n\t\t");
                                for (i = 0x00; i < (unsigned int)res; i++)
                                {
                                    NFCPRINT("%02X ", MifareResp[i]);
                                }
                                NFCPRINT("\n\n");

                                res = nfcTag_transceive(TagInfo.handle, MifareWriteCmd, sizeof(MifareWriteCmd), MifareResp, 255, 500);
                                if (0x00 == res)
                                {
                                    NFCPRINT("\n\t\tRAW Tag transceive failed\n");
                                }
                                else
                                {
                                    NFCPRINT("\n\t\tMifare Write command sent\n\t\tResponse : \n\t\t");
                                    for (i = 0x00; i < (unsigned int)res; i++)
                                    {
                                        NFCPRINT("%02X ", MifareResp[i]);
                                    }
                                    NFCPRINT("\n\n");
                                }
                            }
                        }
                    }
                    else if (TARGET_TYPE_MIFARE_UL == TagInfo.technology)
                    {
                        NFCPRINT("\n\tMIFARE UL card\n");
                        NFCPRINT("\t\tMifare Read command: ");
                        for (i = 0x00; i < (unsigned int)sizeof(MifareReadCmd); i++)
                        {
                            NFCPRINT("%02X ", MifareReadCmd[i]);
                        }
                        NFCPRINT("\n");
                        res = nfcTag_transceive(TagInfo.handle, MifareReadCmd, sizeof(MifareReadCmd), MifareResp, 16, 500);
                        if (0x00 == res)
                        {
                            NFCPRINT("\n\t\tRAW Tag transceive failed\n");
                        }
                        else
                        {
                            NFCPRINT("\n\t\tMifare Read command sent\n\t\tResponse : \n\t\t");
                            for (i = 0x00; i < (unsigned int)res; i++)
                            {
                                NFCPRINT("%02X ", MifareResp[i]);
                            }
                            NFCPRINT("\n\n");
                        }
                    }
                    else
                    {
                        NFCPRINT("\n\tNot a MIFARE card\n");
                    }
                }
                if (0x03 == mode)
                {
                    res = WriteTag(TagInfo, msgToSend, len);
                    if (0x00 == res)
                    {
                        NFCPRINT("\tWrite Tag OK\n\tRead back data\n");
                        res = nfcTag_isNdef(TagInfo.handle, &NDEFinfo);
                        if (0x01 == res)
                        {
                            PrintfNDEFInfo(NDEFinfo);
                            PrintNDEFContent(&TagInfo, &NDEFinfo, NULL, 0x00);
                        }
                    }
                    else
                    {
                        NFCPRINT("\tWrite Tag Failed\n");
                    }
                }
                num_tags = getNumTags();
                if (num_tags > 1)
                {
                    tag_count++;
                    if (tag_count < num_tags)
                    {
                        NFCPRINT("\tMultiple tags found, selecting next tag...\n");
                        selectNextTag();
                    }
                    else
                    {
                        tag_count = 0;
                    }
                }
                framework_LockMutex(g_devLock);
            }
            else if (eDevType_P2P == g_Dev_Type) /*P2P Detected*/
            {
                framework_UnlockMutex(g_devLock);
                NFCPRINT("\tDevice Found\n");

                if (2 == mode)
                {
                    SnepPush(msgToSend, len);
                }

                framework_LockMutex(g_SnepClientLock);

                if (eSnepClientState_READY == g_SnepClientState)
                {
                    g_SnepClientState = eSnepClientState_WAIT_OFF;
                    framework_WaitMutex(g_SnepClientLock, 0);
                }

                framework_UnlockMutex(g_SnepClientLock);
                framework_LockMutex(g_devLock);
            }
            else if (eDevType_READER == g_Dev_Type)
            {
                framework_LockMutex(g_HCELock);
                do
                {
                    framework_UnlockMutex(g_devLock);

                    if (eHCEState_NONE == g_HCEState)
                    {
                        g_HCEState = eHCEState_WAIT_DATA;
                        framework_WaitMutex(g_HCELock, 0x00);
                    }

                    if (eHCEState_DATA_RECEIVED == g_HCEState)
                    {
                        g_HCEState = eHCEState_NONE;

                        if (HCE_data != NULL)
                        {
                            NFCPRINT("\t\tReceived data from remote device : \n\t\t");

                            for (i = 0x00; i < HCE_dataLenght; i++)
                            {
                                NFCPRINT("%02X ", HCE_data[i]);
                            }

                            /*Call HCE response builder*/
                            T4T_NDEF_EMU_Next(HCE_data, HCE_dataLenght, HCEReponse, &HCEResponseLen);
                            free(HCE_data);
                            HCE_dataLenght = 0x00;
                            HCE_data = NULL;
                        }
                        framework_UnlockMutex(g_HCELock);
                        res = nfcHce_sendCommand(HCEReponse, HCEResponseLen);
                        framework_LockMutex(g_HCELock);
                        if (0x00 == res)
                        {
                            NFCPRINT("\n\n\t\tResponse sent : \n\t\t");
                            for (i = 0x00; i < HCEResponseLen; i++)
                            {
                                NFCPRINT("%02X ", HCEReponse[i]);
                            }
                            NFCPRINT("\n\n");
                        }
                        else
                        {
                            NFCPRINT("\n\n\t\tFailed to send response\n\n");
                        }
                    }
                    framework_LockMutex(g_devLock);
                } while (eDevState_PRESENT == g_DevState);
                framework_UnlockMutex(g_HCELock);
            }
            else
            {
                framework_UnlockMutex(g_devLock);
                break;
            }

            if (eDevState_PRESENT == g_DevState)
            {
                g_DevState = eDevState_WAIT_DEPARTURE;
                framework_WaitMutex(g_devLock, 0);
                if (eDevType_P2P == DevTypeBck)
                {
                    NFCPRINT("\tDevice Lost\n\n");
                }
                DevTypeBck = eDevType_NONE;
            }
            else if (eDevType_P2P == DevTypeBck)
            {
                NFCPRINT("\tDevice Lost\n\n");
            }
        }

        framework_UnlockMutex(g_devLock);
    } while (0x01);

    return res;
}

void *ExitThread(void *pContext)
{
    NFCPRINT("                              ... press enter to quit ...\n\n");

    getchar();

    framework_LockMutex(g_SnepClientLock);

    if (eSnepClientState_WAIT_OFF == g_SnepClientState || eSnepClientState_WAIT_READY == g_SnepClientState)
    {
        g_SnepClientState = eSnepClientState_EXIT;
        framework_NotifyMutex(g_SnepClientLock, 0);
    }
    else
    {
        g_SnepClientState = eSnepClientState_EXIT;
    }
    framework_UnlockMutex(g_SnepClientLock);

    framework_LockMutex(g_devLock);

    if (eDevState_WAIT_ARRIVAL == g_DevState || eDevState_WAIT_DEPARTURE == g_DevState)
    {
        g_DevState = eDevState_EXIT;
        framework_NotifyMutex(g_devLock, 0);
    }
    else
    {
        g_DevState = eDevState_EXIT;
    }

    framework_UnlockMutex(g_devLock);
    return NULL;
}

int InitEnv()
{
    eResult tool_res = FRAMEWORK_SUCCESS;
    int res = 0x00;

    tool_res = framework_CreateMutex(&g_devLock);
    if (FRAMEWORK_SUCCESS != tool_res)
    {
        res = 0xFF;
    }

    if (0x00 == res)
    {
        tool_res = framework_CreateMutex(&g_SnepClientLock);
        if (FRAMEWORK_SUCCESS != tool_res)
        {
            res = 0xFF;
        }
    }

    if (0x00 == res)
    {
        tool_res = framework_CreateMutex(&g_HCELock);
        if (FRAMEWORK_SUCCESS != tool_res)
        {
            res = 0xFF;
        }
    }
    if (0x00 == res)
    {
        tool_res = framework_CreateThread(&g_ThreadHandle, ExitThread, NULL);
        if (FRAMEWORK_SUCCESS != tool_res)
        {
            res = 0xFF;
        }
    }

    return res;
}