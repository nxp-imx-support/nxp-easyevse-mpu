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

#pragma once

#define MAX_ENDPOINTS 10
#define STDOUT_FD 1
#define ERRNO_MAX_SIZE 512
#define MAX_EVSE_CURRENT 16
#define RUNTIME_ISSUE -1

#if defined(imx93evk)
#define SERIAL_PORT "/dev/ttyLP2"
#elif defined(imx8mnevk)
#define SERIAL_PORT "/dev/ttymxc2"
#else
#define SERIAL_PORT "UNKNOWN"
#endif

typedef enum
{
	GET_DATA,
	PUSH_DATA
} ClientAction_t;

typedef enum
{
	METER,
	NFC,
	GUI,
	CLOUD,
	SERVER,
	ANY,
	UNKNOWN_ENDPOINT
} EndPoint_t;

typedef enum
{
	NONE,
	ERRORS_ONLY,
	ALL
} LoggingLevel_t;

struct EndPointItem
{
	int fd;
	int pid;
	int isConnected;
	EndPoint_t type;
	char endpointString[20];
};

struct fd_assoc
{
	int server_fd;

	// endpoints list used for information tracking about connected clients - status, type, file descriptor
	struct EndPointItem clients_arr[MAX_ENDPOINTS];
	int clients_arr_size;

	// endpoints deny list used to prohibit unwanted clients to be connected
	EndPoint_t deny_list[MAX_ENDPOINTS];
	int deny_list_size;
};

struct meter_data
{
	char chgsta[8];
	double current;
	double power;
	double voltage;
};

struct nfc_data
{
	char id[32];
};

struct cloud_data
{
	double grid_pwr_lim;
	double tariff_cost;
	double tariff_rate;
	int charge_stop;
};

struct cloud_credentials
{
	char provisioningType[32];
	char connectionString[512];
	char deviceID[64];
	char scopeID[64];
	char devicePK[128];
	char *hostname;
};

struct gui_data
{
	double battery;
};

struct evse_loc
{
	double lat;
	double lon;
	double alt;
};

struct common_data
{
	char evse_id[32];
	double charge_cost;
	double evse_rating;
	int temperature;
	char vehicle_auth[16];
	char chg_time[16];
	int bat_capacity;
	int fw_vers;
	struct evse_loc location;
	int charge_rate;
};

struct evse_data
{
	struct common_data cmn;
	struct meter_data met;
	struct nfc_data nfc;
	struct gui_data gui;
	struct cloud_data cloud;
};

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
