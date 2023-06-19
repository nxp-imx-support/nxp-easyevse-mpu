/*************************************************************************/
/* Copyright (c) Microsoft. All rights reserved.                         */
/* Copyright 2023 NXP                                                    */
/* Licensed under the MIT license. See LICENSE.MIT file in the project   */
/* root for full license information.                                    */
/*************************************************************************/


#include <cjson/cJSON.h>
#include "../include/comms.h"
#include "../include/utils.h"
#include "../include/typedefs.h"

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

static IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol;
static IOTHUB_DEVICE_CLIENT_HANDLE device_handle;
static size_t g_message_count_send_confirmations = 0;

// TODO ADD SUPPORT FOR X:509 certificates
/* DPS consts and variables */
SECURE_DEVICE_TYPE hsm_type;
PROV_DEVICE_TRANSPORT_PROVIDER_FUNCTION prov_transport;
PROV_DEVICE_HANDLE prov_device_handle;
PROV_DEVICE_RESULT prov_device_result;
volatile static bool g_registration_complete = false;

// DeviceId for this device as determined by the DPS client runtime.
static char *g_dpsDeviceId;

static const char *global_prov_uri = "global.azure-devices-provisioning.net";

MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(PROV_DEVICE_RESULT, PROV_DEVICE_RESULT_VALUE);

// Log file descriptor
// default logging output is stdout
volatile int logFileDesc = STDOUT_FD;

// Logging level
LoggingLevel_t logLevel = ALL;

// CLOUD socket file descriptor
int endpointFd;

// GUI identity variable defined only in gui_app.c
EndPoint_t identity = CLOUD;

// CLOUD Data
volatile struct cloud_data desired_properties;
volatile struct cloud_data reported_properties;
volatile static int terminate_cycle = 0;
static int old_chg_stop = 0;
int desired_version;
int reported_version;
volatile bool twin_updated = false;
bool first_execution = true;
bool first_connection = true;
volatile static struct cloud_credentials credentials;

// Environment variable used to specify how app connects to hub and the two possible values.
// First time DPS should be used to retrieve Host Name and create a Connection String (CS)
// The next times, the program will use the saved generated CS for reconnecting.
static const char g_securityTypeEnvironmentVariable[] = "IOTCENTRAL_DEVICE_SECURITY_TYPE";
// Environment variable used to specify this application's connection string.
static const char g_connectionStringEnvironmentVariable[] = "IOTCENTRAL_DEVICE_CONNECTION_STRING";
static const char g_deviceIDEnvironmentVariable[] = "IOTCENTRAL_DEVICE_ID";
static const char g_scopeIDEnvironmentVariable[] = "IOTCENTRAL_SCOPE_ID";
static const char g_devicePKEnvironmentVariable[] = "IOTCENTRAL_DEVICE_PK";
static const char g_securityTypeConnectionStringValue[] = "connectionString";
static const char g_securityTypeDpsValue[] = "DPS";
static const char g_deviceCSEnvironmentVariable[] = "IOTCENTRAL_DEVICE_CS";

/* This is a callback triggered everytime a telemetry message is confirmed by IoTHub
 */
static void send_confirm_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void *userContextCallback)
{
    (void)userContextCallback;
    // When a message is sent this callback will get invoked
    g_message_count_send_confirmations++;
    (void)printf("[CLOUD] Confirmation callback  received for message %lu with result %s\r\n", (unsigned long)g_message_count_send_confirmations, MU_ENUM_TO_STRING(IOTHUB_CLIENT_CONFIRMATION_RESULT, result));
}
/* This is the callback to inform the status of the last reported properties */
static void reportedStateCallback(int status_code, void *userContextCallback)
{
    (void)userContextCallback;
    printf("[CLOUD] Device Twin reported properties update completed with result: %d\r\n", status_code);
}

char *SerializeCloudData()
{
    char *buffer = NULL;
    cJSON *json_cloud_data = NULL, *json_data = NULL;
    int res;

    json_data = cJSON_CreateObject();
    json_cloud_data = cJSON_CreateObject();

    cJSON_AddNumberToObject(json_cloud_data, "grid_pwr_lim", reported_properties.grid_pwr_lim);
    cJSON_AddNumberToObject(json_cloud_data, "tariff_cost", reported_properties.tariff_cost);
    cJSON_AddNumberToObject(json_cloud_data, "tariff_rate", reported_properties.tariff_rate);
    cJSON_AddNumberToObject(json_cloud_data, "chg_stop", terminate_cycle);
    cJSON_AddNumberToObject(json_data, "Client", identity);
    cJSON_AddItemToObject(json_data, "Data", json_cloud_data);

    buffer = cJSON_PrintUnformatted(json_data);
    cJSON_Delete(json_data);

    return buffer;
}

char *UpdateSerializeReportedMessage()
{
    char *buffer = NULL;
    cJSON *json_reported = NULL;
    int res;

    json_reported = cJSON_CreateObject();
    printf("[CLOUD] Desired version: %d Reported version: %d \n", desired_version, reported_version);
    // Properties were updated in the cloud, it is neecessary to update the reported properties
    // and prepare the message with the updated properties
    if (reported_version < desired_version)
    {
        if (reported_properties.grid_pwr_lim != desired_properties.grid_pwr_lim)
        {
            reported_properties.grid_pwr_lim = desired_properties.grid_pwr_lim;
            cJSON_AddNumberToObject(json_reported, "GridPowerLimit2", reported_properties.grid_pwr_lim);
        }
        if (reported_properties.tariff_cost != desired_properties.tariff_cost)
        {
            reported_properties.tariff_cost = desired_properties.tariff_cost;
            cJSON_AddNumberToObject(json_reported, "tariffcost", reported_properties.tariff_cost);
        }
        if (reported_properties.tariff_rate != desired_properties.tariff_rate)
        {
            reported_properties.tariff_rate = desired_properties.tariff_rate;
            cJSON_AddNumberToObject(json_reported, "Tariff", reported_properties.tariff_rate);
        }
    }
    else
    {
        // Versions are equal - just initialize the reported with the value from desired properties
        // in case the properties were synchronized (same versions), but the device has turned off
        // and turned on.
        reported_properties = desired_properties;
    }

    buffer = cJSON_PrintUnformatted(json_reported);
    cJSON_Delete(json_reported);

    return buffer;
}

static void deviceTwinCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char *payLoad, size_t size, void *userContextCallback)
{
    char *reported_message = NULL;
    cJSON *json_desired = NULL;
    json_desired = cJSON_Parse(payLoad);

    if (cJSON_HasObjectItem(json_desired, "GridPowerLimit2"))
    {
        desired_properties.grid_pwr_lim = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "GridPowerLimit2"));
    }
    if (cJSON_HasObjectItem(json_desired, "Tariff"))
    {
        desired_properties.tariff_rate = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "Tariff"));
    }
    if (cJSON_HasObjectItem(json_desired, "tariffcost"))
    {
        desired_properties.tariff_cost = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "tariffcost"));
    }
    desired_version = (int)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "$version"));
    cJSON_Delete(json_desired);

    // Update reported properties and package on a message
    reported_message = UpdateSerializeReportedMessage();
    IoTHubDeviceClient_SendReportedState(device_handle, (const unsigned char *)reported_message, strlen(reported_message), reportedStateCallback, NULL);

    printf("[CLOUD] DTC: %s\n", payLoad);
}

void UpdateChargeStatus(char *message)
{
    cJSON *json_message;
    int current_chg_stop;

    json_message = cJSON_Parse(message);
    json_message = cJSON_GetObjectItem(json_message, "Data");

    current_chg_stop = (int)cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "chg_stop"));

    if (first_execution)
    {
        old_chg_stop = current_chg_stop;
        first_execution = false;
    }
    else
    {
        // If the server is asking to clean the flag
        // Ensure terminate_cycle is only cleaned if the
        // change was propagated
        if (old_chg_stop == 1 & current_chg_stop == 0)
        {
            terminate_cycle = 0;
        }
    }
}

char *FilterTelemetry(char *message)
{
    cJSON *telemetry_data = NULL, *location_data = NULL, *json_message, *json_message_location;
    char *filtered_telemetry = NULL;

    telemetry_data = cJSON_CreateObject();
    json_message = cJSON_Parse(message);
    json_message = cJSON_GetObjectItem(json_message, "Data");

    if (first_connection)
    {
        location_data = cJSON_CreateObject();
        json_message_location = cJSON_GetObjectItemCaseSensitive(json_message, "evse_location");
	    cJSON_AddStringToObject(telemetry_data, "evseid", cJSON_GetStringValue(cJSON_GetObjectItem(json_message, "evse_id")));
        cJSON_AddNumberToObject(telemetry_data, "firmwareV", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "fw_vers")));
        cJSON_AddNumberToObject(location_data, "lon", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message_location, "lon")));
        cJSON_AddNumberToObject(location_data, "lat", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message_location, "lat")));
        cJSON_AddNumberToObject(location_data, "alt", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message_location, "alt")));
        cJSON_AddItemToObject(telemetry_data, "evselocation", location_data);
        cJSON_AddNumberToObject(telemetry_data, "evselimit", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "evse_rating")));
        first_connection = false;
    }
    else
    {
        cJSON_AddStringToObject(telemetry_data, "vehicleid", cJSON_GetStringValue(cJSON_GetObjectItem(json_message, "card_id")));
        cJSON_AddStringToObject(telemetry_data, "vehicleauthentic2", cJSON_GetStringValue(cJSON_GetObjectItem(json_message, "vehicle_auth")));
        cJSON_AddNumberToObject(telemetry_data, "batterycapacity", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "bat_capacity")));
        cJSON_AddNumberToObject(telemetry_data, "irms", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "current")));
        cJSON_AddNumberToObject(telemetry_data, "vrms", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "voltage")));
        cJSON_AddNumberToObject(telemetry_data, "kwh", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "power")));
        cJSON_AddNumberToObject(telemetry_data, "temperature", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "temperature")));
        cJSON_AddNumberToObject(telemetry_data, "ChargeRate", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "chg_rate")));
        cJSON_AddStringToObject(telemetry_data, "TimeRemaining", cJSON_GetStringValue(cJSON_GetObjectItem(json_message, "chg_time")));
        cJSON_AddNumberToObject(telemetry_data, "chargecost", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "chg_cost")));
    }
    // Common
    cJSON_AddNumberToObject(telemetry_data, "battery", cJSON_GetNumberValue(cJSON_GetObjectItem(json_message, "battery_value")));
    cJSON_AddStringToObject(telemetry_data, "chargestatus", cJSON_GetStringValue(cJSON_GetObjectItem(json_message, "chgsta")));

    filtered_telemetry = cJSON_PrintUnformatted(telemetry_data);
    cJSON_Delete(telemetry_data);

    return filtered_telemetry;
}

void UpdateCycle(int serv_fd, EndPoint_t clientType)
{
    char messageBuffer[CLOUD_MESSAGE_BUFFER_SIZE];
    int flags[] = {0, 0}; // first - read flag, second - modify flag
    int retCode;
    IOTHUB_MESSAGE_HANDLE message_handle;

    while (1)
    {
        // clear messageBuffer before read
        memset(messageBuffer, 0, sizeof(messageBuffer));

        // read the message from server
        retCode = ReadMessage(serv_fd, messageBuffer, sizeof(messageBuffer), clientType);

        // if read failed, return from UpdateCyle
        if (retCode == -1)
        {
            return;
        }

        // Retrieve the flags value
        ParseJSONMessage(messageBuffer, flags, identity);

        if (flags[PUSH_DATA])
        {
            // Update charging status
            printf("[CLOUD] Send data to cloud\n");
            printf("[CLOUD] %s\n", messageBuffer);
            UpdateChargeStatus(messageBuffer);
            char *telemetry = FilterTelemetry(messageBuffer);
            printf("[CLOUD] %s\n", telemetry);
            message_handle = IoTHubMessage_CreateFromString(telemetry);
            IoTHubDeviceClient_SendEventAsync(device_handle, message_handle, send_confirm_callback, NULL);
            free(telemetry);
            flags[PUSH_DATA] = 0;
        }

        if (flags[GET_DATA])
        {

            char *message = SerializeCloudData();
            retCode = SendMessage(serv_fd, message, strlen(message), clientType);
            free(message);
            if (retCode == -1)
            {

                return;
            }
            flags[GET_DATA] = 0;
        }
    }
}

/* This is a callback to inform the status of connection to IoTHub
 */
static void connection_status_callback(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void *user_context)
{
    (void)reason;
    (void)user_context;
    // This sample DOES NOT take into consideration network outages.
    if (result == IOTHUB_CLIENT_CONNECTION_AUTHENTICATED)
    {
        (void)printf("[CLOUD] The device client is connected to IoTCentral\r\n");
    }
    else
    {
        (void)printf("[CLOUD] The device client has been disconnected\r\n");
    }
}

// provisioningRegisterCallback is called by the DPS client when the DPS server has either succeeded or failed the DPS
// provisioning process.  We store in global variables the result code and (on success) the IoT Hub and device Id so we can
// later use this to create an IoT Hub connection.

static void register_device_callback(PROV_DEVICE_RESULT register_result, const char *iothub_uri, const char *device_id, void *user_context)
{
    (void)user_context;
    if (register_result == PROV_DEVICE_RESULT_OK)
    {
        // Copy Provisioning information to create IoT Hub client
        if ((mallocAndStrcpy_s(&credentials.hostname, iothub_uri) != 0))
        {
            printf("[CLOUD] Unable to copy provisioning information");
        }
        (void)printf("\r\n[CLOUD] Provisioning Information received from service: %s, deviceId: %s\r\n", credentials.hostname, device_id);
    }
    else
    {
        (void)printf("\r\n[CLOUD] Failure provisioning device: %s\r\n", MU_ENUM_TO_STRING(PROV_DEVICE_RESULT, register_result));
    }
    g_registration_complete = true;
}

int InitDPS()
{
    int ret;
    char errorBuffer[ERRNO_MAX_SIZE];
    // TODO, create option for X.509 certificates
    hsm_type = SECURE_DEVICE_TYPE_SYMMETRIC_KEY;

    // Load Device ID, Scope IP and Primary Key
    LoadVariable(g_deviceIDEnvironmentVariable, credentials.deviceID, sizeof(credentials.deviceID));
    LoadVariable(g_scopeIDEnvironmentVariable, credentials.scopeID, sizeof(credentials.scopeID));
    LoadVariable(g_devicePKEnvironmentVariable, credentials.devicePK, sizeof(credentials.devicePK));

    ret = prov_dev_security_init(hsm_type);
    if (ret != 0)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, PROV_SEC_INIT_FAIL, errorBuffer, logFileDesc);
    }

    ret = prov_dev_set_symmetric_key_info(credentials.deviceID, credentials.devicePK);
    if (ret != 0)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, PROV_SET_SK_FAIL, errorBuffer, logFileDesc);
    }

    prov_device_handle = Prov_Device_Create(global_prov_uri, credentials.scopeID, prov_transport);
    if (prov_device_handle == NULL)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, PROV_DEV_CREATE_FAIL, errorBuffer, logFileDesc);
        return -1;
    }

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    // Setting the Trusted Certificate. This is only necessary on systems without
    // built in certificate stores.
    Prov_Device_SetOption(prov_device_handle, OPTION_TRUSTED_CERT, certificates);
#endif // SET_TRUSTED_CERT_IN_SAMPLES

    prov_device_result = Prov_Device_Register_Device(prov_device_handle, register_device_callback, NULL, NULL, NULL);

    if (prov_device_result == PROV_DEVICE_RESULT_OK)
    {
        (void)printf("\r\n[CLOUD] Provisioning Device\r\n\r\n");
        // Wait until the device registration is completed.
        do
        {
            ThreadAPI_Sleep(1000);
        } while (!g_registration_complete);
        Prov_Device_Destroy(prov_device_handle);
    }
    else
    {
        Prov_Device_Destroy(prov_device_handle);
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, PROV_DEV_REG_FAIL, errorBuffer, logFileDesc);
        return -1;
    }

    ret = iothub_security_init(IOTHUB_SECURITY_TYPE_SYMMETRIC_KEY);
    if (ret != 0)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, IOTHUB_SET_INIT_FAIL, errorBuffer, logFileDesc);
    }

    return 0;
}

void GenerateCS()
{
    /* Generate Connection String */

    snprintf(credentials.connectionString,
             sizeof(credentials.connectionString),
             "HostName=%s;DeviceId=%s;SharedAccessKey=%s",
             credentials.hostname,
             credentials.deviceID,
             credentials.devicePK);

    /* Set CS as the provisioning type - the next connections
       the device will be provisioned and there is no need to
       use DPS again.
     */

    UpdateConfigFile(g_securityTypeEnvironmentVariable, "connectionString", NULL);

    /* Set CS environment variable for the next connection */

    UpdateConfigFile(g_deviceCSEnvironmentVariable, credentials.connectionString, g_deviceCSEnvironmentVariable);
}

/* This function should implement the action to be executed when the command terminate change cycle is received */
void TerminateChargeCycle()
{
    // Set terminate cycle to 1
    // This update is NOT imediately propagated to server.
    // instead, the next time server request a reading,
    // it will update itself and take the actions accordingly.
    // This value is also updated (cleaned) by the server.
    // So, to keep consistency, before setting it, save the previous
    // value to old_chg_stop to avoid that terminate_cycle being cleaned
    // without being propated.
    if (!first_execution)
    {
        old_chg_stop = terminate_cycle;
    }
    terminate_cycle = 1;
}

/* Callback called whenever a method invocation happens */
static int deviceMethodCallback(const char *method_name, const unsigned char *payload, size_t size, unsigned char **response, size_t *response_size, void *userContextCallback)
{
    (void)userContextCallback;
    (void)payload;
    (void)size;
    int result;

    if (strcmp("terminate", method_name) == 0)
    {
        TerminateChargeCycle();
        const char deviceMethodResponse[] = "{\"status\":\"OK\"}";
        *response_size = sizeof(deviceMethodResponse) - 1;
        *response = malloc(*response_size);
        (void)memcpy(*response, deviceMethodResponse, *response_size);
        result = 200;
    }
    else
    {
        // All other entries are ignored.
        const char deviceMethodResponse[] = "{ }";
        *response_size = sizeof(deviceMethodResponse) - 1;
        *response = malloc(*response_size);
        (void)memcpy(*response, deviceMethodResponse, *response_size);
        result = -1;
    }

    return result;
}

/* Retrieve all Twin */
static void getCompleteDeviceTwinOnDemandCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char *payLoad, size_t size, void *userContextCallback)
{
    (void)update_state;
    (void)userContextCallback;
    cJSON *json_payload = NULL, *json_desired = NULL, *json_reported = NULL;
    json_payload = cJSON_Parse(payLoad);
    printf("[CLOUD] GetTwinAsync result:\r\n%.*s\r\n", (int)size, payLoad);
    json_desired = cJSON_GetObjectItem(json_payload, "desired");
    json_reported = cJSON_GetObjectItem(json_payload, "reported");

    // Check if payload has the desired properties already configured in the cloud device identity
    if (cJSON_HasObjectItem(json_desired, "GridPowerLimit2"))
    {
        desired_properties.grid_pwr_lim = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "GridPowerLimit2"));
    }
    if (cJSON_HasObjectItem(json_desired, "Tariff"))
    {
        desired_properties.tariff_rate = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "Tariff"));
    }
    if (cJSON_HasObjectItem(json_desired, "tariffcost"))
    {
        desired_properties.tariff_cost = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "tariffcost"));
    }

    desired_version = (int)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "$version"));
    reported_version = (int)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_reported, "$version"));

    cJSON_Delete(json_payload);
    twin_updated = true;
}

void CloudDeinit(int signal)
{

    prov_dev_security_deinit();
    // Clean up the IoT Hub SDK handle.
    IoTHubDeviceClient_Destroy(device_handle);
    // Free all the sdk subsystem
    IoTHub_Deinit();
    // Call generic clean up
    CleanUp(signal);
}

int InitCloud()
{

    // Initializes the IoT Hub Client System.
    char errorBuffer[ERRNO_MAX_SIZE];
    int ret;
    protocol = MQTT_Protocol;
    char *reported_properties_message = NULL;

    // Load the type of provisioning
    LoadVariable(g_securityTypeEnvironmentVariable, credentials.provisioningType, sizeof(credentials.provisioningType));
    printf("[CLOUD] [PROV TYPE] %s\n", credentials.provisioningType);

    ret = IoTHub_Init();
    if (ret != 0)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, IOTHUB_INIT_FAIL, errorBuffer, logFileDesc);
        return -1;
    }

    if (strcmp(credentials.provisioningType, "DPS") == 0)
    {
        prov_transport = Prov_Device_MQTT_Protocol;
        ret = InitDPS();
        if (ret == -1)
        {
            return ret;
        }
        GenerateCS();
    }
    else if (strcmp(credentials.provisioningType, "connectionString") == 0)
    {
        // Load the CS
        LoadVariable(g_deviceCSEnvironmentVariable, credentials.connectionString, sizeof(credentials.connectionString));
        printf("[CLOUD] [cs] %ld %s\n", strlen(credentials.connectionString), credentials.connectionString);
    }
    else
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, PROV_TYPE_INVALID, errorBuffer, logFileDesc);
        return -1;
    }

    device_handle = IoTHubDeviceClient_CreateFromConnectionString(credentials.connectionString, protocol);
    if (device_handle == NULL)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, CREATE_DEV_HANDLE_FAIL_CS, errorBuffer, logFileDesc);
        return -1;
    }

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    // Setting the Trusted Certificate. This is only necessary on systems without
    // built in certificate stores.
    IoTHubDeviceClient_SetOption(device_handle, OPTION_TRUSTED_CERT, certificates);
    printf("[CLOUD] Using Developing certificated for SSL\n");
#endif // SET_TRUSTED_CERT_IN_SAMPLES

    // Setting connection status callback to get indication of connection to iothub
    ret = IoTHubDeviceClient_SetConnectionStatusCallback(device_handle, connection_status_callback, NULL);
    if (ret != IOTHUB_CLIENT_OK)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, IOTHUB_CONN_CALL_FAIL, errorBuffer, logFileDesc);
    }

    // Set method invocation callback
    ret = IoTHubDeviceClient_SetDeviceMethodCallback(device_handle, deviceMethodCallback, NULL);
    if (ret != IOTHUB_CLIENT_OK)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, IOTHUB_METH_INVOC_FAIL, errorBuffer, logFileDesc);
    }

    // Init desired and reported properties equally
    desired_properties.grid_pwr_lim = 0;
    desired_properties.tariff_cost = 0;
    desired_properties.tariff_rate = 0;

    reported_properties.grid_pwr_lim = 0;
    reported_properties.tariff_cost = 0;
    reported_properties.tariff_rate = 0;

    // Retrieve the device twin and have the values for properties
    (void)IoTHubDeviceClient_GetTwinAsync(device_handle, getCompleteDeviceTwinOnDemandCallback, NULL);
    if (ret != IOTHUB_CLIENT_OK)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, IOTHUB_GET_TWIN_FAIL, errorBuffer, logFileDesc);
    }

    // Wait until the twin is received and the desired properties updated successfully
    while (!twin_updated);

    reported_properties_message = UpdateSerializeReportedMessage();
    if(reported_properties_message == NULL)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, CJSON_PRINT_MESSAGE_FAIL, errorBuffer, logFileDesc);
    }

    printf("[CLOUD] Reporting: %s\n", reported_properties_message);
    // Send reported properties
    ret = IoTHubDeviceClient_SendReportedState(device_handle, (const unsigned char *)reported_properties_message, strlen(reported_properties_message), reportedStateCallback, NULL);
    if (ret != IOTHUB_CLIENT_OK)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, IOTHUB_GET_TWIN_FAIL, errorBuffer, logFileDesc);
    }

    // Subscribe to desired properties update notifications
    ret = IoTHubDeviceClient_SetDeviceTwinCallback(device_handle, deviceTwinCallback, NULL);
    if (ret != IOTHUB_CLIENT_OK)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, IOTHUB_SET_TWIN_CALL_FAIL, errorBuffer, logFileDesc);
    }
}

int main(int argc, char *argv[])
{
    struct tm dt;
    int retCode;

    // setup signal handling
    HandleSignal(SIGUSR1, CloudDeinit);

    // prepare the logging file structure based on evse.conf file parsed by server
    if (argc == 2)
    {
        logLevel = atoi(argv[1]);
        if (logLevel > NONE)
        {
            PrepareLoggingEnv(identity);
        }
    }

    printf("[CLOUD] Starting Cloud Client\n");

    retCode = InitCloud();
    if (retCode == -1)
    {
        CloudDeinit(RUNTIME_ISSUE);
        return retCode;
    }

    endpointFd = InitSocket(identity);
    if (endpointFd == -1)
    {
        CloudDeinit(RUNTIME_ISSUE);
        return endpointFd;
    }

    retCode = SendIdentity(endpointFd, identity);
    if (retCode == -1)
    {
        CloudDeinit(RUNTIME_ISSUE);
        return retCode;
    }

    UpdateCycle(endpointFd, identity);

    CloudDeinit(RUNTIME_ISSUE);

    return 0;
}