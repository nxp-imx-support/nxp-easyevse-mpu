/*************************************************************************/
/* Copyright (c) Microsoft. All rights reserved.                         */
/* Copyright 2023-2024 NXP                                                    */
/* Licensed under the MIT license. See LICENSE.MIT file in the project   */
/* root for full license information.                                    */
/*************************************************************************/

#include "easyevse/cloud_api.h"

#include <openssl/store.h>
#include <openssl/provider.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include "snw_common.h"

#define SECURITY_TYPE SECURE_DEVICE_TYPE_X509
#define BEGIN_PRIVATE_KEY_STR "-----BEGIN EC PRIVATE KEY-----\n"
#define END_PRIVATE_KEY_STR "\n-----END EC PRIVATE KEY-----"
#define OPENSSL11_SE05X_CNF_FILE "/etc/ssl/openssl11_sss_se050.cnf"

EVP_PKEY *p_client_pkey       = NULL;
OSSL_LIB_CTX *ossl_ctx = NULL;
ex_sss_boot_ctx_t gdirectSeSessionCtx;

#define MAX_DER_CERT_SIZE    1024
U8 clientCerDer[MAX_DER_CERT_SIZE];
size_t clientCerDerLen = MAX_DER_CERT_SIZE;
uint8_t key[550];
size_t keybytelen = sizeof(key);
char encodedData[500] = {0};

/* Cloud data structures & configuration */
IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol;
IOTHUB_DEVICE_CLIENT_HANDLE device_handle;
size_t g_message_count_send_confirmations = 0;

// TODO ADD SUPPORT FOR X:509 certificates
/* DPS consts and variables */
SECURE_DEVICE_TYPE hsm_type;
PROV_DEVICE_TRANSPORT_PROVIDER_FUNCTION prov_transport;
PROV_DEVICE_HANDLE prov_device_handle;
PROV_DEVICE_RESULT prov_device_result;
volatile bool g_registration_complete = false;

// DeviceId for this device as determined by the DPS client runtime.
char *g_dpsDeviceId;

const char *global_prov_uri = "global.azure-devices-provisioning.net";

MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(PROV_DEVICE_RESULT, PROV_DEVICE_RESULT_VALUE);

// CLOUD Data
volatile struct cloud_properties desired_properties;
volatile struct cloud_properties reported_properties;
volatile int terminate_cycle = 0;
int old_chg_stop = 0;
int desired_version;
int reported_version;
volatile bool twin_updated = false;
bool first_execution = true;
bool first_connection = true;
volatile struct cloud_credentials credentials;

// Environment variable used to specify how app connects to hub and the two possible values.
// First time DPS should be used to retrieve Host Name and create a Connection String (CS)
// The next times, the program will use the saved generated CS for reconnecting.
const char g_securityTypeEnvironmentVariable[] = "IOTCENTRAL_DEVICE_SECURITY_TYPE";
// Environment variable used to specify this application's connection string.
const char g_connectionStringEnvironmentVariable[] = "IOTCENTRAL_DEVICE_CONNECTION_STRING";
const char g_deviceIDEnvironmentVariable[] = "IOTCENTRAL_DEVICE_ID";
const char g_scopeIDEnvironmentVariable[] = "IOTCENTRAL_SCOPE_ID";
const char g_devicePKEnvironmentVariable[] = "IOTCENTRAL_DEVICE_PK";
const char g_securityTypeConnectionStringValue[] = "connectionString";
const char g_securityTypeDpsValue[] = "DPS";
const char g_deviceHUEnvironmentVariable[] = "IOTCENTRAL_DEVICE_HUB_URI";
const char g_certIDEnvironmentVariable[] = "IOTCENTRAL_CERT_ID";
const char g_keyIDEnvironmentVariable[] = "IOTCENTRAL_KEY_ID";
const char g_modelIDEnvironmentVariable[] = "IOTCENTRAL_MODEL_ID";

char *cert;

// Log file descriptor
// default logging output is stdout
volatile int logFileDesc = STDOUT_FD;

// Logging level
LoggingLevel_t logLevel = ALL;

// CLOUD identity variable
EndPoint_t identity = CLOUD;

/* This is a callback triggered everytime a telemetry message is confirmed by IoTHub
 */
void send_confirm_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void *userContextCallback)
{
    (void)userContextCallback;
    // When a message is sent this callback will get invoked
    g_message_count_send_confirmations++;
    // (void)printf("[CLOUD] Confirmation callback  received for message %lu with result %s\r\n", (unsigned long)g_message_count_send_confirmations, MU_ENUM_TO_STRING(IOTHUB_CLIENT_CONFIRMATION_RESULT, result));
}

/* This is the callback to inform the status of the last reported properties */
void reportedStateCallback(int status_code, void *userContextCallback)
{
    (void)userContextCallback;
    printf("[CLOUD] Device Twin reported properties update completed with result: %d\r\n", status_code);
}

char *UpdateSerializeReportedMessage()
{
    char *buffer = NULL;
    cJSON *json_reported = NULL;
    int res;

    json_reported = cJSON_CreateObject();
    //printf("[CLOUD] Desired version: %d Reported version: %d \n", desired_version, reported_version);
    // Properties were updated in the cloud, it is neecessary to update the reported properties
    // and prepare the message with the updated properties
    if (reported_version < desired_version)
    {
        if (reported_properties.grid_pwr_lim != desired_properties.grid_pwr_lim)
        {
            reported_properties.grid_pwr_lim = desired_properties.grid_pwr_lim;
            cJSON_AddNumberToObject(json_reported, "GridPowerLimit", reported_properties.grid_pwr_lim);
        }
        if (reported_properties.tariff_cost != desired_properties.tariff_cost)
        {
            reported_properties.tariff_cost = desired_properties.tariff_cost;
            cJSON_AddNumberToObject(json_reported, "TariffCost", reported_properties.tariff_cost);
        }
        if (reported_properties.tariff_rate != desired_properties.tariff_rate)
        {
            reported_properties.tariff_rate = desired_properties.tariff_rate;
            cJSON_AddNumberToObject(json_reported, "TariffRate", reported_properties.tariff_rate);
        }
    }
    else
    {
        // Versions are equal - just initialize the reported with the value from desired properties
        // in case the properties were synchronized (same versions), but the device has turned off
        // and turned on.
        reported_properties.grid_pwr_lim = desired_properties.grid_pwr_lim;
        reported_properties.tariff_cost = desired_properties.tariff_cost;
        reported_properties.tariff_rate = desired_properties.tariff_rate;
    }

    C_sendReportedProperties(&reported_properties);

    buffer = cJSON_PrintUnformatted(json_reported);
    cJSON_Delete(json_reported);

    return buffer;
}

void deviceTwinCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char *payLoad, size_t size, void *userContextCallback)
{
    char *reported_message = NULL;
    cJSON *json_desired = NULL;
    json_desired = cJSON_Parse(payLoad);

    if (cJSON_HasObjectItem(json_desired, "GridPowerLimit"))
    {
        desired_properties.grid_pwr_lim = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "GridPowerLimit"));
    }
    if (cJSON_HasObjectItem(json_desired, "TariffRate"))
    {
        desired_properties.tariff_rate = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "TariffRate"));
    }
    if (cJSON_HasObjectItem(json_desired, "TariffCost"))
    {
        desired_properties.tariff_cost = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "TariffCost"));
    }
    desired_version = (int)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "$version"));
    cJSON_Delete(json_desired);

    // Update reported properties and package on a message
    reported_message = UpdateSerializeReportedMessage();
    IoTHubDeviceClient_SendReportedState(device_handle, (const unsigned char *)reported_message, strlen(reported_message), reportedStateCallback, NULL);

    printf("[CLOUD] DTC: %s\n", payLoad);
}

/* This is a callback to inform the status of connection to IoTHub
 */
void connection_status_callback(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void *user_context)
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

void register_device_callback(PROV_DEVICE_RESULT register_result, const char *iothub_uri, const char *device_id, void *user_context)
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
    char payload[50];
    int max_len = sizeof payload;

    // TODO, create option for X.509 certificates
    hsm_type = SECURITY_TYPE;

    // Load Device ID, Scope IP and Primary Key
    LoadVariable(CLOUD_CONF_FILE, g_deviceIDEnvironmentVariable, credentials.deviceID, sizeof(credentials.deviceID));
    LoadVariable(CLOUD_CONF_FILE, g_scopeIDEnvironmentVariable, credentials.scopeID, sizeof(credentials.scopeID));
#if SECURITY_TYPE == SECURE_DEVICE_TYPE_SYMMETRIC_KEY
    LoadVariable(CLOUD_CONF_FILE, g_devicePKEnvironmentVariable, credentials.devicePK, sizeof(credentials.devicePK));
#endif
    printf("[CLOUD] credentials.deviceID %s\n", credentials.deviceID);
    printf("[CLOUD] credentials.scopeID %s\n", credentials.scopeID);

    ret = prov_dev_security_init(hsm_type);
    if (ret != 0)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, PROV_SEC_INIT_FAIL, errorBuffer, logFileDesc);
    }
#if SECURITY_TYPE == SECURE_DEVICE_TYPE_SYMMETRIC_KEY
    ret = prov_dev_set_symmetric_key_info(credentials.deviceID, credentials.devicePK);
    if (ret != 0)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, PROV_SET_SK_FAIL, errorBuffer, logFileDesc);
    }
#endif
    prov_device_handle = Prov_Device_Create(global_prov_uri, credentials.scopeID, prov_transport);
    if (prov_device_handle == NULL)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, PROV_DEV_CREATE_FAIL, errorBuffer, logFileDesc);
        return -1;
    }

    LoadVariable(CLOUD_CONF_FILE, g_modelIDEnvironmentVariable, credentials.modelId, sizeof(credentials.modelId));
    snprintf(payload, max_len, "{\"modelId\": %s}" , credentials.modelId);
    Prov_Device_Set_Provisioning_Payload(prov_device_handle, payload);

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    // Setting the Trusted Certificate. This is only necessary on systems without
    // built in certificate stores.
    Prov_Device_SetOption(prov_device_handle, OPTION_TRUSTED_CERT, certificates);
#endif // SET_TRUSTED_CERT_IN_SAMPLES

#if SECURITY_TYPE == SECURE_DEVICE_TYPE_X509
        LoadVariable(CLOUD_CONF_FILE, g_keyIDEnvironmentVariable, credentials.keyId, sizeof(credentials.keyId));

        Prov_Device_SetOption(prov_device_handle, PROV_REGISTRATION_ID, credentials.deviceID);
        Prov_Device_SetOption(prov_device_handle, OPTION_X509_CERT, cert);
        Prov_Device_SetOption(prov_device_handle, OPTION_X509_PRIVATE_KEY, encodedData);
#endif /* SECURE_DEVICE_TYPE_X509 */

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

    ret = iothub_security_init(SECURITY_TYPE);
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
             "HostName=%s;DeviceId=%s;x509=true",
             credentials.hostname,
             credentials.deviceID);

    /* Set CS as the provisioning type - the next connections
       the device will be provisioned and there is no need to
       use DPS again.
     */

    UpdateConfigFile(CLOUD_CONF_FILE, g_securityTypeEnvironmentVariable, "connectionString", NULL);

    /* Set CS environment variable for the next connection */

    UpdateConfigFile(CLOUD_CONF_FILE, g_deviceHUEnvironmentVariable, credentials.connectionString, g_deviceHUEnvironmentVariable);
}

/* This function should implement the action to be executed when the command terminate change cycle is received */
void TerminateChargeCycle()
{
    terminate_cycle = 1;
    C_sendStopReq(&terminate_cycle);
    terminate_cycle = 0;
}

/* Callback called whenever a method invocation happens */
int deviceMethodCallback(const char *method_name, const unsigned char *payload, size_t size, unsigned char **response, size_t *response_size, void *userContextCallback)
{
    (void)userContextCallback;
    (void)payload;
    (void)size;
    int result;

    if (strcmp("TerminateChargeCycle", method_name) == 0)
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
void getCompleteDeviceTwinOnDemandCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char *payLoad, size_t size, void *userContextCallback)
{
    (void)update_state;
    (void)userContextCallback;
    cJSON *json_payload = NULL, *json_desired = NULL, *json_reported = NULL;
    json_payload = cJSON_Parse(payLoad);
    printf("[CLOUD] GetTwinAsync result:\r\n%.*s\r\n", (int)size, payLoad);
    json_desired = cJSON_GetObjectItem(json_payload, "desired");
    json_reported = cJSON_GetObjectItem(json_payload, "reported");

    // Check if payload has the desired properties already configured in the cloud device identity
    if (cJSON_HasObjectItem(json_desired, "GridPowerLimit"))
    {
        desired_properties.grid_pwr_lim = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "GridPowerLimit"));
    }
    if (cJSON_HasObjectItem(json_desired, "TariffRate"))
    {
        desired_properties.tariff_rate = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "TariffRate"));
    }
    if (cJSON_HasObjectItem(json_desired, "TariffCost"))
    {
        desired_properties.tariff_cost = (double)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "TariffCost"));
    }

    desired_version = (int)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_desired, "$version"));
    reported_version = (int)cJSON_GetNumberValue(cJSON_GetObjectItemCaseSensitive(json_reported, "$version"));

    cJSON_Delete(json_payload);
    twin_updated = true;
}

void CloudDeinit()
{
    prov_dev_security_deinit();
    // Clean up the IoT Hub SDK handle.
    IoTHubDeviceClient_Destroy(device_handle);
    // Free all the sdk subsystem
    IoTHub_Deinit();
    free(cert);
}

int CreateRefKey(int keybytelen, int key_id_int)
{
	unsigned char pre_string[7] = {0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20};
	unsigned char mid_string[17] = {0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00};
	unsigned char priv_buffer[32] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA5, 0xA6, 0xB5, 0xB6, 0xA5, 0xA6, 0xB5, 0xB6, 0x10, 0x00};
	int len_pub_key = keybytelen;
	char *pub_key_pointer = (char *) key;
	int key_id_index = 18; // id where key id starts in priv_buffer

	int len_ref_key_binary = sizeof(priv_buffer) + sizeof(pre_string) + sizeof(mid_string) + len_pub_key;
	char *ref_key = malloc(len_ref_key_binary);
	if (ref_key == NULL)
	{
	   printf("ref_key is NULL. Exit");
	   return -1;
	}
	else
	{
		memcpy(ref_key, pre_string, sizeof(pre_string)); // copy in final binary buffer the pre string
		memcpy(ref_key + sizeof(pre_string), priv_buffer, sizeof(priv_buffer)); // copy in final binary buffer the priv_buffer

		memcpy(ref_key + sizeof(pre_string) + key_id_index, (char*)(&key_id_int) + 3, 1); // overwrite the key id with the actual key id
		memcpy(ref_key + sizeof(pre_string) + key_id_index + 1, (char*)(&key_id_int) + 2, 1); // overwrite the key id with the actual key id
		memcpy(ref_key + sizeof(pre_string) + key_id_index + 2, (char*)(&key_id_int) + 1, 1); // overwrite the key id with the actual key id
		memcpy(ref_key + sizeof(pre_string) + key_id_index + 3, (char*)(&key_id_int) + 0, 1); // overwrite the key id with the actual key id

		memcpy(ref_key + sizeof(pre_string) + sizeof(priv_buffer), mid_string, sizeof(mid_string)); // copy in final binary buffer the mid string
		memcpy(ref_key + sizeof(pre_string) + sizeof(priv_buffer) + sizeof(mid_string), pub_key_pointer, len_pub_key); // copy the pub_key in the ref_key array
	}

	strcpy(encodedData, BEGIN_PRIVATE_KEY_STR);
	int encoded_bytes = EVP_EncodeBlock((unsigned char *)(&encodedData[strlen(BEGIN_PRIVATE_KEY_STR)]), ref_key, len_ref_key_binary);
	strcpy(&encodedData[strlen(BEGIN_PRIVATE_KEY_STR) + encoded_bytes], END_PRIVATE_KEY_STR);

	return 0;
}
int InitCloud()
{

    // Initializes the IoT Hub Client System.
    char errorBuffer[ERRNO_MAX_SIZE];
    int ret;
    protocol = MQTT_Protocol;
    char *reported_properties_message = NULL;

    PrepareLoggingEnv(identity);

    // Load the type of provisioning
    LoadVariable(CLOUD_CONF_FILE, g_securityTypeEnvironmentVariable, credentials.provisioningType, sizeof(credentials.provisioningType));
    printf("[CLOUD] [PROV TYPE] %s\n", credentials.provisioningType);

    ret = IoTHub_Init();
    if (ret != 0)
    {
        sprintf(errorBuffer, "Line: %d in %s. errno: %d - %s",
                (__LINE__), __func__, errno, strerror(errno));
        LogEvent(identity, IOTHUB_INIT_FAIL, errorBuffer, logFileDesc);
        return -1;
    }

#if SECURITY_TYPE == SECURE_DEVICE_TYPE_X509
    char randy[500];
    RAND_bytes(&randy, 128);

    int certId;
    X509 *x;
    unsigned char *buf;

    LoadVariable(CLOUD_CONF_FILE, g_certIDEnvironmentVariable, credentials.certId, sizeof(credentials.certId));

    memset(&gdirectSeSessionCtx, 0, sizeof(ex_sss_boot_ctx_t));

    certId = (int)strtol(credentials.certId, NULL, 0);

    /* Session is used to retrive cert from SE */
    int rc = wrapConnectToSe(&gdirectSeSessionCtx);
    if (rc != 0) {
	printf( "Failed to connect to Secure Element.\n");
	return rc;
    }

    rc = seGetClientCertificate(&(gdirectSeSessionCtx.ks), certId, clientCerDer, &clientCerDerLen);
    if (rc != 0) {
	printf("Failed to retrieve client certificate.\n");
	return rc;
    }

    /* Set up buf and len to point to the input buffer. */
    buf = clientCerDer;
    x = d2i_X509(NULL, (const unsigned char **)&buf, clientCerDerLen);
    if (x == NULL){
	printf("Failed to convert client certificate.\n");
	return rc;
    }

    BIO *cert_bio = BIO_new(BIO_s_mem());
    if (cert_bio == NULL) {
	printf("cert_bio failed");
	return rc;
    }
    rc = PEM_write_bio_X509(cert_bio, x);
    if (rc == 0) {
	BIO_free(cert_bio);
	printf("PEM_write_bio_X509 failed");
	return rc;
    }

    cert = malloc (sizeof (char) * 2000);
    BIO_read(cert_bio, cert, 20000);
    BIO_free(cert_bio);
    LoadVariable(CLOUD_CONF_FILE, g_keyIDEnvironmentVariable, credentials.keyId, sizeof(credentials.keyId));
    int key_id_int = (int)strtol(credentials.keyId, NULL, 0);

    rc = seGetClientKey(&(gdirectSeSessionCtx.ks), key_id_int, key, &keybytelen);
    if (rc != 0) {
	printf("Failed to retrieve key.\n");
	return rc;
    }

    rc= CreateRefKey(keybytelen, key_id_int);
    if (rc != 0) {
	printf("Failed to retrieve key.\n");
	return rc;
    }
    wrapDisconnectFromSe(&gdirectSeSessionCtx);
    RAND_bytes(&randy, 128);
#endif

    if (strcmp(credentials.provisioningType, "DPS") == 0)
    {
        prov_transport = Prov_Device_MQTT_Protocol;
        ret = InitDPS();
        if (ret == -1)
        {
	    printf("\nInit DPS failed.\n");
            return ret;
        }
        GenerateCS();
    }
    else if (strcmp(credentials.provisioningType, "connectionString") == 0)
    {
        // Load the CS
        LoadVariable(CLOUD_CONF_FILE, g_deviceHUEnvironmentVariable, credentials.connectionString, sizeof(credentials.connectionString));
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


    IoTHubDeviceClient_SetOption(device_handle, OPTION_X509_CERT, cert);
    IoTHubDeviceClient_SetOption(device_handle, OPTION_X509_PRIVATE_KEY, encodedData);

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
