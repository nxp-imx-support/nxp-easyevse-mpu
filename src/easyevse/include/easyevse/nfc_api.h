/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/

#ifndef NFCAPI_H
#define NFCAPI_H

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <linux_nfc_api.h>
#include "easyevse/tools.h"
#include "easyevse/utils.h"

typedef enum eDevState
{
	eDevState_NONE,
	eDevState_WAIT_ARRIVAL,
	eDevState_PRESENT,
	eDevState_WAIT_DEPARTURE,
	eDevState_DEPARTED,
	eDevState_EXIT
} eDevState;

typedef enum eSnepClientState
{
	eSnepClientState_WAIT_OFF,
	eSnepClientState_OFF,
	eSnepClientState_WAIT_READY,
	eSnepClientState_READY,
	eSnepClientState_EXIT
} eSnepClientState;

typedef enum eHCEState
{
	eHCEState_NONE,
	eHCEState_WAIT_DATA,
	eHCEState_DATA_RECEIVED,
	eHCEState_EXIT
} eHCEState;

typedef enum eDevType
{
	eDevType_NONE,
	eDevType_TAG,
	eDevType_P2P,
	eDevType_READER
} eDevType;

typedef enum T4T_NDEF_EMU_state_t
{
	Ready,
	NDEF_Application_Selected,
	CC_Selected,
	NDEF_Selected
} T4T_NDEF_EMU_state_t;

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

void	T4T_NDEF_EMU_FillRsp(unsigned char *pRsp, unsigned short offset, unsigned char length);
void 	T4T_NDEF_EMU_SetRecord(unsigned char *pRecord, unsigned short Record_size, T4T_NDEF_EMU_Callback_t *cb);
void 	T4T_NDEF_EMU_Reset(void);
void 	T4T_NDEF_EMU_Next(unsigned char *pCmd, unsigned char *pRsp, unsigned short *pRsp_size);
void 	onDataReceived(unsigned char *data, unsigned int data_length);
void 	onHostCardEmulationActivated(unsigned char mode);
void 	onHostCardEmulationDeactivated();
void 	onTagArrival(nfc_tag_info_t *pTagInfo);
void 	onTagDeparture(void);
void 	onDeviceArrival(void);
void 	onDeviceDeparture(void);
void 	onMessageReceived(unsigned char *message, unsigned int length);
void 	onSnepClientReady();
void 	onSnepClientClosed();
int 	InitMode(int tag, int p2p, int hce);
void 	DeinitPollMode();
int 	SnepPush(unsigned char* msgToPush, unsigned int len);
int 	WriteTag(nfc_tag_info_t TagInfo, unsigned char* msgToPush, unsigned int len);
void 	PrintfNDEFInfo(ndef_info_t pNDEFinfo);
void 	open_uri(const char* uri);
void 	PrintNDEFContent(nfc_tag_info_t* TagInfo, ndef_info_t* NDEFinfo, unsigned char* ndefRaw, int ndefRawLen);
int 	WaitDeviceArrival(int mode, unsigned char* msgToSend, unsigned int len, void C_sendID(char*));
void* 	ExitThread();
int 	InitEnv();

#endif // NFCAPI_H
