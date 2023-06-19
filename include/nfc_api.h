/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/



#include <ctype.h>
#include <linux_nfc_api.h>
#include <semaphore.h>
#include <pthread.h>
#include "typedefs.h"
#include "utils.h"
#include <tools.h>

extern sem_t semaphore;

extern void* g_ThreadHandle;
extern void* g_devLock;
extern void* g_SnepClientLock;
extern void* g_HCELock;
extern eDevState g_DevState;
extern eDevType g_Dev_Type;
extern eSnepClientState g_SnepClientState;
extern eHCEState g_HCEState;
extern nfc_tag_info_t g_TagInfo;
extern nfcTagCallback_t g_TagCB;
extern nfcHostCardEmulationCallback_t g_HceCB;
extern nfcSnepServerCallback_t g_SnepServerCB;
extern nfcSnepClientCallback_t g_SnepClientCB;
extern unsigned char *HCE_data;
extern unsigned int HCE_dataLenght;
extern const unsigned char T4T_NDEF_EMU_APP_Select[];
extern const unsigned char T4T_NDEF_EMU_CC[];
extern const unsigned char T4T_NDEF_EMU_CC_Select[];
extern const unsigned char T4T_NDEF_EMU_NDEF_Select[];
extern const unsigned char T4T_NDEF_EMU_Read[];
extern const unsigned char T4T_NDEF_EMU_OK[];
extern const unsigned char T4T_NDEF_EMU_NOK[];
extern unsigned char *pT4T_NdefRecord;
extern unsigned short T4T_NdefRecord_size;

typedef void T4T_NDEF_EMU_Callback_t (unsigned char*, unsigned short);
extern T4T_NDEF_EMU_state_t eT4T_NDEF_EMU_State;
extern T4T_NDEF_EMU_Callback_t *pT4T_NDEF_EMU_PushCb;

void T4T_NDEF_EMU_FillRsp(unsigned char *pRsp, unsigned short offset, unsigned char length);
void T4T_NDEF_EMU_SetRecord(unsigned char *pRecord, unsigned short Record_size, T4T_NDEF_EMU_Callback_t *cb);
void T4T_NDEF_EMU_Reset(void);
void T4T_NDEF_EMU_Next(unsigned char *pCmd, unsigned short Cmd_size, unsigned char *pRsp, unsigned short *pRsp_size);
void onDataReceived(unsigned char *data, unsigned int data_length);
void onHostCardEmulationActivated(unsigned char mode);
void onHostCardEmulationDeactivated();
void onTagArrival(nfc_tag_info_t *pTagInfo);
void onTagDeparture(void);
void onDeviceArrival(void);
void onDeviceDeparture(void);
void onMessageReceived(unsigned char *message, unsigned int length);
void onSnepClientReady();
void onSnepClientClosed();
int InitMode(int tag, int p2p, int hce);
void DeinitPollMode();
int SnepPush(unsigned char* msgToPush, unsigned int len);
int WriteTag(nfc_tag_info_t TagInfo, unsigned char* msgToPush, unsigned int len);
void PrintfNDEFInfo(ndef_info_t pNDEFinfo);
void open_uri(const char* uri);
void PrintNDEFContent(nfc_tag_info_t* TagInfo, ndef_info_t* NDEFinfo, unsigned char* ndefRaw, unsigned int ndefRawLen);
int WaitDeviceArrival(int mode, unsigned char* msgToSend, unsigned int len);
void* ExitThread(void* pContext);
int InitEnv();