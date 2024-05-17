/*************************************************************************/
/* Copyright (c) Microsoft. All rights reserved.                         */
/* Copyright 2023-2024 NXP                                               */
/* Licensed under the MIT license. See LICENSE.MIT file in the project   */
/* root for full license information.                                    */
/*************************************************************************/

#ifndef CLOUDAPI_H
#define CLOUDAPI_H

#include "easyevse/utils.h"

/* Cloud client includes*/
#include "iothub.h"
#include "iothub_device_client.h"
#include "iothubtransportmqtt.h"

// TODO: Remove it, certificate for test only
#ifdef SET_TRUSTED_CERT_IN_SAMPLES
#include "certs.h"
#include "iothub_client_options.h"
#include "azure_c_shared_utility/shared_util_options.h"
#endif /* SET_TRUSTED_CERT_IN_SAMPLES */

/* DPS necessary includes */
#include "azure_prov_client/prov_device_client.h"
#include "azure_prov_client/prov_security_factory.h"
#include "azure_prov_client/iothub_security_factory.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_prov_client/prov_transport_mqtt_client.h"

/* Cloud data structures & configuration */

extern IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol;
extern IOTHUB_DEVICE_CLIENT_HANDLE device_handle;
extern size_t g_message_count_send_confirmations;

// TODO ADD SUPPORT FOR X:509 certificates
/* DPS consts and variables */
extern SECURE_DEVICE_TYPE hsm_type;
extern PROV_DEVICE_TRANSPORT_PROVIDER_FUNCTION prov_transport;
extern PROV_DEVICE_HANDLE prov_device_handle;
extern PROV_DEVICE_RESULT prov_device_result;
extern volatile bool g_registration_complete;

// DeviceId for this device as determined by the DPS client runtime.
extern char *g_dpsDeviceId;

extern const char *global_prov_uri;

// CLOUD Data
extern volatile struct cloud_properties desired_properties;
extern volatile struct cloud_properties reported_properties;
extern volatile int terminate_cycle;
extern int old_chg_stop;
extern int desired_version;
extern int reported_version;
extern volatile bool twin_updated;
extern bool first_execution;
extern bool first_connection;
extern volatile struct cloud_credentials credentials;

// Environment variable used to specify how app connects to hub and the two possible values.
// First time DPS should be used to retrieve Host Name and create a Connection String (CS)
// The next times, the program will use the saved generated CS for reconnecting.
extern const char g_securityTypeEnvironmentVariable[];
// Environment variable used to specify this application's connection string.
extern const char g_connectionStringEnvironmentVariable[];
extern const char g_deviceIDEnvironmentVariable[];
extern const char g_scopeIDEnvironmentVariable[];
extern const char g_devicePKEnvironmentVariable[];
extern const char g_securityTypeConnectionStringValue[];
extern const char g_securityTypeDpsValue[];
extern const char g_deviceCSEnvironmentVariable[];
extern const char g_modelIDEnvironmentVariable[];

void    send_confirm_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void *userContextCallback);
void    reportedStateCallback(int status_code, void *userContextCallback);
char    *UpdateSerializeReportedMessage();
void    deviceTwinCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char *payLoad, size_t size, void *userContextCallback);
void    connection_status_callback(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void *user_context);
void    register_device_callback(PROV_DEVICE_RESULT register_result, const char *iothub_uri, const char *device_id, void *user_context);
int     InitDPS();
void    GenerateCS();
void    TerminateChargeCycle();
int     deviceMethodCallback(const char *method_name, const unsigned char *payload, size_t size, unsigned char **response, size_t *response_size, void *userContextCallback);
void    getCompleteDeviceTwinOnDemandCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char *payLoad, size_t size, void *userContextCallback);
void    CloudDeinit();
int     InitCloud();
void    C_sendReportedProperties(const volatile struct cloud_properties *reported_properties);
void    C_sendStopReq(const bool *reported_stop);

#endif // CLOUDAPI_H
