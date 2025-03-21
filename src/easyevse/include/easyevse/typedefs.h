/******************************************************************************
 *
 * Copyright 2015-2021, 2023-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 ******************************************************************************/

#ifndef TYPEDEFS_H
#define TYPEDEFS_H

#define MAX_ENDPOINTS 10
#define STDOUT_FD 1
#define ERRNO_MAX_SIZE 512
#define MAX_EVSE_CURRENT 32
#define RUNTIME_ISSUE -1
#define KNOWN_CLIENTS_TYPE_NO 4
#define ACTION_NAME_SIZE 32

typedef enum
{
	UART_BRIDGE,
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

struct cloud_properties
{
	double grid_pwr_lim;
	double tariff_cost;
	double tariff_rate;
};

struct cloud_credentials
{
	char provisioningType[32];
	char connectionString[512];
	char deviceID[64];
	char scopeID[64];
	char certId[256];
	char keyId[256];
	char modelId[256];
	char devicePK[128];
	char *hostname;
};
#endif //TYPEDEFS_H
