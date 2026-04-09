/*
* Copyright 2023-2026 NXP
* NXP Confidential and Proprietary. This software is owned or controlled by NXP and may only be used strictly in
* accordance with the applicable license terms. By expressly accepting such terms or by downloading, installing,
* activating and/or otherwise using the software, you are agreeing that you have read, and that you agree to
* comply with and are bound by, such license terms.  If you do not agree to be bound by the applicable license
* terms, then you may not retain, install, activate or otherwise use the software.
*/

/*********************
  *      INCLUDES
  *********************/
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <stdlib.h>
#include "lvgl.h"
#include "custom.h"
#include <string.h>
#include <unistd.h>
#include "MQTTClient.h"
#include <dlfcn.h>
#include "gui_guider.h"
#include "events_init.h"
#include "widgets_init.h"
#include <ctype.h>
// Add these includes at the top if not already present
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>


/*********************
 *      DEFINES
 *********************/
#define ADDRESS     "localhost:1883" // Example broker 
#define CLIENTID    "MQTTClient" 
// #define TOPIC       "everest_external/nodered/1/cmd/set_max_current" 
#define TOPIC       "everest_external/nodered/1/#" 
// #define PAYLOAD     "unplug" 
#define PAYLOAD  "12"   
// "sleep 1;iec_wait_pwr_ready;sleep 1;draw_power_regulated 16,3;sleep 36000;unplug"  
#define QOS         1 
#define TIMEOUT     10000L 

/**********************
 *  MQTT TOPICS ARRAY
 *********************/
// Centralized MQTT topics - used for initial subscription and reconnection
static const char* MQTT_TOPICS[] = {
    "everest_external/nodered/1/powermeter/totalKWattHr",
    "everest_external/nodered/1/powermeter/totalKw",
    "everest_external/nodered/1/state/temperature",
    "everest_external/nodered/1/state/state_string",
    "everest_api/ocpp/var/connection_status",
    "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/evse_id",
    "everest_external/nodered/1/ev/ev_id",
    "everest_external/nodered/1/ev/battery_level",
    "everest_external/nodered/1/iso15118/mode",
    "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/selected_protocol",
    "everest_external/nodered/1/iso15118/voltage",
    "everest_external/nodered/1/iso15118/direction",
    "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/hw_capabilities",
    "everest_api/1/auth_consumer/auth_api/e2m/token_validation_status",
    // "everest_external/nodered/1/nfc/card_type",      // Commented - not currently used
    // "everest_external/nodered/1/nfc/card_status",    // Commented - not currently used
    "everest_api/evse_manager_1/var/powermeter"
};

static const int MQTT_TOPICS_COUNT = sizeof(MQTT_TOPICS) / sizeof(MQTT_TOPICS[0]);
/**********************
 *      TYPEDEFS
 **********************/

/**********************
 *  STATIC PROTOTYPES
 **********************/

// MQTT helper function prototype
int subscribe_to_mqtt_topics(void);
int unsubscribe_from_mqtt_topics(void);

/**********************
 *  STATIC VARIABLES
 **********************/

/**
 * Create a demo application
 */
MQTTClient client;
MQTTClient_message pubmsg = MQTTClient_message_initializer;
extern int screen_digital_clock_1_hour_value;
extern int screen_digital_clock_1_min_value;
extern int screen_digital_clock_1_sec_value;
extern char screen_digital_clock_1_meridiem[];
static time_t last_update_time = 0;
static const int UPDATE_INTERVAL_SECONDS = 1;
char final_energy[20];
char hour[10];
char minutes[10];
char seconds[10];
char am_pm[10];
bool is_new_session=false;
bool is_session_started=false;
float battery_level = 20.0f;
bool active_session=false;
int max_limit=25;
float totalKWattHr = 0.000f;
int set_paused=0;
float mqtt_power_kw = 0.0f;
float mqtt_energy_kwh = 0.0f;
float mqtt_battery_level = -1.0f;  // -1 means no MQTT data available
static bool start_time_captured = false;
static bool pause_time_captured = false;
static bool session_end_processed = false;

// Time calculation code end

// Add these global variables at the top
static time_t last_mqtt_message_time = 0;
static const int MQTT_TIMEOUT_SECONDS = 2;  // Show overlay if no MQTT for 2+ seconds

static bool mqtt_connected = false;
static lv_timer_t * mqtt_reconnect_timer = NULL;

// Add subscription tracking
static bool mqtt_topics_subscribed = false;
static unsigned long mqtt_reconnection_count = 0;

// ============================================
// STATIC BUFFERS FOR LVGL LABELS (PREVENT MEMORY LEAK)
// ============================================
// Pre-allocated buffers reused for all label updates
// This prevents LVGL from allocating new memory on every update (which causes 7MB/hour leak)
static char label_state_buffer[64] = "Initializing...";
static char label_energy_buffer[32] = "0.0 kWh";
static char label_temp_buffer[16] = "0";
static char label_power_buffer[16] = "0";
static char label_battery_buffer[16] = "20.0";
static char label_time_buffer[32] = "--:--:--";
static char label_evse_id_buffer[128] = "EVSE ID: NA";
static char label_ev_id_buffer[128] = "EV ID: NA";
static char label_iso_mode_buffer[32] = "ISO Mode: NA";
static char label_protocol_buffer[64] = "Protocol: NA";
static char label_voltage_buffer[32] = "Voltage: NA";
static char label_direction_buffer[32] = "Direction: NA";
static char label_sigboard_buffer[32] = "Sigboard: NA";
static char label_uid_buffer[64] = "UID: NA";
static char label_card_type_buffer[64] = "Type: NA";
static char label_card_status_buffer[64] = "Status: NA";
static char label_current_buffer[32] = "0.0 A";
static char label_duration_buffer[32] = "00:00:00";
static char label_end_time_buffer[32] = "00:00:00 AM";
static char label_ip_buffer[32] = "(No IP)";
static char label_network_buffer[16] = "Unknown";
static char label_location_buffer[64] = "NXP Plot 1";
static char label_slider1_buffer[16] = "MAX: 0%";
static char label_slider2_buffer[16] = "0%";


// Helper macro to safely update labels without memory allocation
#define UPDATE_LABEL_SAFE(label, buffer, text) \
    do { \
        strncpy(buffer, text, sizeof(buffer) - 1); \
        buffer[sizeof(buffer) - 1] = '\0'; \
        lv_label_set_text_static(label, buffer); \
    } while(0)



// Structure to represent time
typedef struct {
    int hours;
    int minutes;
    int seconds;
    char ampm; // 'A' for AM, 'P' for PM
} Time;

static Time pauseTime;
// Function to convert time to total seconds
int timeToSeconds(Time t) {
    int totalSeconds = 0;
    int hours = t.hours;

    // Handle AM/PM conversion
    if (t.ampm == 'P' && t.hours != 12) {
        hours += 12;
    } else if (t.ampm == 'A' && t.hours == 12) {
        hours = 0;
    }

    totalSeconds += hours * 3600;
    totalSeconds += t.minutes * 60;
    totalSeconds += t.seconds;

    return totalSeconds;
}

// Function to convert total seconds to time format
Time secondsToTime(int totalSeconds) {
    Time t;
    t.hours = (totalSeconds / 3600) % 24;
    t.minutes = (totalSeconds / 60) % 60;
    t.seconds = totalSeconds % 60;
    t.ampm = (t.hours < 12) ? 'A' : 'P';
    if (t.hours == 0) t.hours = 12;
    else if (t.hours > 12) t.hours -= 12;
    return t;
}

int timeToSeconds(Time t);
Time secondsToTime(int totalSeconds);

Time startTime, endTime, diffTime;
int startTimeInSeconds, endTimeInSeconds, diffInSeconds;
// Time calculation code end

// Add this function before custom_init()
static void clock_update_timer_cb(lv_timer_t * timer)
{
    static int last_displayed_second = -1;
    
    // Get current system time
    time_t rawtime;
    struct tm * timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    
    // Only update display when second actually changes
    if (timeinfo->tm_sec != last_displayed_second) {
        set_screen_digital_clock_1();
        last_displayed_second = timeinfo->tm_sec;
    }
}

// Function to get machine IP address from eth1, fallback to other interfaces
void get_machine_ip(char *ip_buffer, size_t buffer_size, char *interface_name, size_t iface_size) {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    char temp_ip[16];
    bool ip_found = false;
    
    // Default values if IP not found
    snprintf(ip_buffer, buffer_size, "(No IP)");
    snprintf(interface_name, iface_size, "none");
    
    if (getifaddrs(&ifaddr) == -1) {
        printf("Error getting IP address\n");
        return;
    }
    
    // First pass: Try to find eth1
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        
        family = ifa->ifa_addr->sa_family;
        
        // Check for IPv4 address specifically on eth1
        if (family == AF_INET && strcmp(ifa->ifa_name, "eth1") == 0) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr->sin_addr, temp_ip, sizeof(temp_ip));
            snprintf(ip_buffer, buffer_size, "(%s)", temp_ip);
            strncpy(interface_name, ifa->ifa_name, iface_size - 1);
            interface_name[iface_size - 1] = '\0';
            // printf("Found IP address: (%s) on interface: %s\n", temp_ip, ifa->ifa_name);
            ip_found = true;
            break;  // Found eth1, stop searching
        }
    }
    
    // Second pass: If eth1 not found, try other interfaces (skip loopback)
    if (!ip_found) {
        printf("eth1 not found, trying other interfaces...\n");
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL)
                continue;
            
            family = ifa->ifa_addr->sa_family;
            
            // Check for IPv4 address on any interface except loopback
            if (family == AF_INET && strcmp(ifa->ifa_name, "lo") != 0) {
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, temp_ip, sizeof(temp_ip));
                snprintf(ip_buffer, buffer_size, "(%s)", temp_ip);
                strncpy(interface_name, ifa->ifa_name, iface_size - 1);
                interface_name[iface_size - 1] = '\0';
                // printf("Found IP address: (%s) on interface: %s (fallback)\n", temp_ip, ifa->ifa_name);
                ip_found = true;
                break;  // Found alternative interface, stop searching
            }
        }
    }
    
    freeifaddrs(ifaddr);
    
    // Log final status
    if (!ip_found) {
        printf("Warning: No IP address found on any interface\n");
    }
}


// Timer callback to update IP address and network type periodically
static void network_status_timer_cb(lv_timer_t * timer)
{
    char ip_address[32];
    char interface_name[16];
    char network_type[16];
    
    // Re-check IP address
    get_machine_ip(ip_address, sizeof(ip_address), interface_name, sizeof(interface_name));
    
    // Re-check network type
    get_network_type(interface_name, network_type, sizeof(network_type));
    
    // Update both labels
    UPDATE_LABEL_SAFE(guider_ui.screen_label_41, label_ip_buffer, ip_address);
    UPDATE_LABEL_SAFE(guider_ui.screen_label_45, label_network_buffer, network_type);

    
    // printf("Network status updated - IP: %s, Type: %s\n", ip_address, network_type);
}

// Function to detect network type (Ethernet or WiFi)
void get_network_type(const char *interface_name, char *type_buffer, size_t buffer_size) {
    int sock;
    struct iwreq wrq;
    struct ifreq ifr;
    
    // Default to Unknown
    snprintf(type_buffer, buffer_size, "Unknown");
    
    // printf("=== Network Type Detection ===\n");
    // printf("Interface name: %s\n", interface_name);
    
    // Skip if no interface name
    if (strcmp(interface_name, "none") == 0) {
        printf("No interface found\n");
        return;
    }
    
    // Create a socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        printf("Error creating socket for network type detection\n");
        return;
    }
    
    // Check if interface is UP and RUNNING
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        printf("Error getting interface flags for %s\n", interface_name);
        close(sock);
        return;
    }
    
    // printf("Interface flags: 0x%x\n", ifr.ifr_flags);
    // printf("IFF_UP: %d\n", !!(ifr.ifr_flags & IFF_UP));
    // printf("IFF_RUNNING: %d\n", !!(ifr.ifr_flags & IFF_RUNNING));
    
    // Check if interface is UP and RUNNING (has active connection)
    if (!(ifr.ifr_flags & IFF_UP) || !(ifr.ifr_flags & IFF_RUNNING)) {
        // printf("Interface %s is not active (no network connection)\n", interface_name);
        snprintf(type_buffer, buffer_size, "Unknown");
        close(sock);
        return;
    }
    
    // Try to get wireless info
    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, interface_name, IFNAMSIZ - 1);
    
    // If ioctl succeeds, it's a wireless interface
    if (ioctl(sock, SIOCGIWNAME, &wrq) >= 0) {
        snprintf(type_buffer, buffer_size, "Wi-Fi");
        // printf("Interface %s is Wi-Fi (active)\n", interface_name);
    } else {
        // Not wireless, it's wired/ethernet
        snprintf(type_buffer, buffer_size, "Wired");
        // printf("Interface %s is Wired/Ethernet (active)\n", interface_name);
    }
    
    close(sock);
    // printf("=== End Detection ===\n");
}


// Timer callback to check MQTT activity
static void mqtt_watchdog_timer_cb(lv_timer_t * timer)
{
    time_t current_time = time(NULL);
    
    // If no MQTT message received for MQTT_TIMEOUT_SECONDS, show cont_4
    if (last_mqtt_message_time > 0 && 
        difftime(current_time, last_mqtt_message_time) > MQTT_TIMEOUT_SECONDS) {
        
        // Only show overlay if not already shown
        if (!lv_obj_has_flag(guider_ui.screen_cont_4, LV_OBJ_FLAG_HIDDEN)) {
            return;  // Already showing overlay
        }
        
        lv_obj_clear_flag(guider_ui.screen_cont_4, LV_OBJ_FLAG_HIDDEN);
        printf("MQTT timeout - showing cont_4 overlay (no messages for %d+ seconds)\n", MQTT_TIMEOUT_SECONDS);
        mqtt_connected = false;  // Mark as disconnected
    }
}


void connectionLost(void *context, char *cause) {
    printf("\n=== MQTT Connection Lost ===\n");
    printf("Cause: %s\n", cause ? cause : "Unknown");
    
    // CRITICAL: Unsubscribe from all topics BEFORE marking as disconnected
    // This prevents duplicate subscriptions on reconnect
    if (mqtt_connected) {
        printf("Cleaning up subscriptions...\n");
        unsubscribe_from_mqtt_topics();
    }
    
    mqtt_connected = false;
    last_mqtt_message_time = 0;
    
    lv_obj_clear_flag(guider_ui.screen_cont_4, LV_OBJ_FLAG_HIDDEN);
    printf("Showing cont_4 overlay (connection lost)\n");
}


// Add MQTT message processing timer
static void mqtt_process_timer_cb(lv_timer_t * timer)
{
    if (mqtt_connected) {
        // Process any pending MQTT messages
        // This ensures messages are handled even if the main loop is busy
        MQTTClient_yield();
    }
}

static void mqtt_reconnect_timer_cb(lv_timer_t * timer)
{
    static unsigned long reconnect_attempts = 0;
    // return;
    if (!mqtt_connected) {
        reconnect_attempts++;
        printf("Attempting MQTT reconnection (attempt #%lu)...\n", reconnect_attempts);
        
        MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
        conn_opts.connectTimeout = 3;
        conn_opts.keepAliveInterval = 60;
        conn_opts.retryInterval = 5;
        conn_opts.cleansession = 1;
        
        int rc = MQTTClient_connect(client, &conn_opts);
        
        if (rc == MQTTCLIENT_SUCCESS) {
            mqtt_reconnection_count++;
            printf("✓ MQTT reconnected successfully! (reconnection #%lu)\n", mqtt_reconnection_count);
            mqtt_connected = true;
            reconnect_attempts = 0;
            
            printf("Ensuring clean subscription state...\n");
            unsubscribe_from_mqtt_topics();
            
            usleep(50000);
            
            printf("Re-subscribing to all topics...\n");
            int subscribed = subscribe_to_mqtt_topics();
            
            if (subscribed == MQTT_TOPICS_COUNT) {
                printf("✓ All topics subscribed successfully\n");
            } else {
                printf("⚠ Warning: Only %d/%d topics subscribed\n", subscribed, MQTT_TOPICS_COUNT);
            }
            
            printf("Reconnected - waiting for EVerest messages...\n");
            
        } else {
            printf("✗ MQTT reconnection failed (code %d), will retry in 10 seconds\n", rc);
            
            if (reconnect_attempts > 20) {
                printf("⚠ Too many failed attempts (%lu), recreating MQTT client...\n", reconnect_attempts);
                
                MQTTClient_destroy(&client);
                MQTTClient_create(&client, ADDRESS, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL);
                MQTTClient_setCallbacks(client, NULL, connectionLost, messageArrived, NULL);
                
                reconnect_attempts = 0;
                printf("MQTT client recreated\n");
            }
        }
    }
}


void custom_init(lv_ui *ui)
{
    /* Add your codes here */
  get_mqtt_state_for_evse();
  set_screen_digital_clock_1();

  lv_timer_t * clock_timer = lv_timer_create(clock_update_timer_cb, 1000, NULL);

  // Show cont_4 overlay by default (waiting for EVerest/MQTT)
  lv_obj_clear_flag(guider_ui.screen_cont_4, LV_OBJ_FLAG_HIDDEN);

  // Create watchdog timer to check MQTT activity every 1 second
  lv_timer_t * mqtt_watchdog = lv_timer_create(mqtt_watchdog_timer_cb, 1000, NULL);
  
  // Create MQTT message processing timer (every 100ms)
  lv_timer_t * mqtt_process = lv_timer_create(mqtt_process_timer_cb, 100, NULL);
  
  // Create MQTT reconnection timer (every 10 seconds)
  mqtt_reconnect_timer = lv_timer_create(mqtt_reconnect_timer_cb, 10000, NULL);

  // setenv("LD_LIBRARY_PATH","/usr/local/lib64",1);
  const char *location = getenv("LOCATION");
  if (location != NULL){
    printf("PATH: %s", location);
    UPDATE_LABEL_SAFE(guider_ui.screen_label_7, label_location_buffer, (char *)location);
	}else{
			UPDATE_LABEL_SAFE(guider_ui.screen_label_7, label_location_buffer, "NXP Plot 1");
	}
  
  // ADD THIS INITIALIZATION FOR EVSE ID
  // Initialize EVSE ID label with default "NA"
  UPDATE_LABEL_SAFE(guider_ui.screen_label_43, label_evse_id_buffer, "EVSE ID: NA");
//   printf("EVSE ID initialized to 'EVSE ID: NA'\n");
  
  // ADD THIS INITIALIZATION FOR EV ID
  // Initialize EV ID label with formatted default
  UPDATE_LABEL_SAFE(guider_ui.screen_label_44, label_ev_id_buffer, "EV ID: NA");
//   printf("EV ID initialized to 'EV ID: NA'\n");

  // Initialize ISO 15118 Mode label
  UPDATE_LABEL_SAFE(guider_ui.screen_label_52, label_iso_mode_buffer, "ISO Mode: NA");
//   printf("ISO 15118 Mode initialized to: ISO Mode: NA\n");
  
  // Initialize ISO 15118 Protocol label
  UPDATE_LABEL_SAFE(guider_ui.screen_label_53, label_protocol_buffer, "Protocol: NA");
//   printf("ISO 15118 Protocol initialized to: Protocol: NA\n");
  
  // Initialize ISO 15118 Voltage label
  UPDATE_LABEL_SAFE(guider_ui.screen_label_54, label_voltage_buffer, "Voltage: NA");
//   printf("ISO 15118 Voltage initialized to: Voltage: NA\n");
  
  // Initialize ISO 15118 Charging Direction label
  UPDATE_LABEL_SAFE(guider_ui.screen_label_55, label_direction_buffer, "Direction: NA");
//   printf("ISO 15118 Direction initialized to: Direction: NA\n");
  // Initialize Sigboard Connection Type label
  UPDATE_LABEL_SAFE(guider_ui.screen_label_56, label_sigboard_buffer, "Sigboard: NA");
//   printf("Sigboard Connection initialized to: Sigboard: NA\n");

  // Initialize NFC Card UID label
  UPDATE_LABEL_SAFE(guider_ui.screen_label_57, label_uid_buffer, "UID: NA");
//   printf("NFC Card UID initialized to: UID: NA\n");

  // Initialize NFC Card Type label
  UPDATE_LABEL_SAFE(guider_ui.screen_label_58, label_card_type_buffer, "Type: NA");
//   printf("NFC Card Type initialized to: Type: NA\n");

  // Initialize NFC Card Status label
  UPDATE_LABEL_SAFE(guider_ui.screen_label_59, label_card_status_buffer, "Status: NA");
  lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
//   printf("NFC Card Status initialized to: Status: NA\n");

  // Initialize Current L1 display
  UPDATE_LABEL_SAFE(guider_ui.screen_label_60, label_current_buffer, "0.0 A");
//   printf("Current L1 initialized to: 0.0 A\n");




  lv_obj_add_event_cb(ui->screen_sw_1, screen_sw_1_event_custom_handler, LV_EVENT_ALL, ui);
  lv_obj_add_event_cb(ui->screen_sw_2, screen_sw_2_custom_event_custom_handler, LV_EVENT_ALL, ui);
  //lv_obj_add_event_cb(ui->screen_img_18, screen_img_18_custom_event_custom_handler, LV_EVENT_ALL, ui);
  //lv_obj_add_event_cb(ui->screen_img_19, screen_img_19_custom_event_custom_handler, LV_EVENT_ALL, ui);
  lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
  lv_obj_add_event_cb(ui->screen_slider_1, screen_slider_1_event_custom_handler, LV_EVENT_VALUE_CHANGED, NULL);
  lv_obj_add_event_cb(ui->screen_slider_2, screen_slider_2_event_custom_handler, LV_EVENT_VALUE_CHANGED, NULL);
  
  //Write style for screen_bar_1, Part: LV_PART_MAIN, State: LV_STATE_DEFAULT.
  lv_obj_set_style_bg_opa(ui->screen_bar_1, 100, LV_PART_MAIN|LV_STATE_DEFAULT);
  lv_obj_set_style_bg_color(ui->screen_bar_1, lv_color_hex(0x58c100), LV_PART_MAIN|LV_STATE_DEFAULT);
  // lv_obj_set_style_bg_grad_dir(ui->screen_bar_1, LV_GRAD_DIR_NONE, LV_PART_MAIN|LV_STATE_DEFAULT);
  
  //Write style for screen_bar_1, Part: LV_PART_INDICATOR, State: LV_STATE_DEFAULT.
  lv_obj_set_style_bg_opa(ui->screen_bar_1, 255, LV_PART_INDICATOR|LV_STATE_DEFAULT);
  lv_obj_set_style_bg_color(ui->screen_bar_1, lv_color_hex(0x26a000), LV_PART_INDICATOR|LV_STATE_DEFAULT);
  // lv_obj_set_style_bg_grad_dir(ui->screen_bar_1, LV_GRAD_DIR_NONE, LV_PART_INDICATOR|LV_STATE_DEFAULT);
  
  // Update Progress value
  lv_bar_set_value(guider_ui.screen_bar_1, 65, LV_ANIM_OFF);
  
  // Add IP address display for label_41 and network type for label_45
    char ip_address[32];
    char interface_name[16];
    char network_type[16];
    
    get_machine_ip(ip_address, sizeof(ip_address), interface_name, sizeof(interface_name));
    UPDATE_LABEL_SAFE(guider_ui.screen_label_41, label_ip_buffer, ip_address);
    // printf("Machine IP set to label_41: %s\n", ip_address);
    
    // Get and display network type
    get_network_type(interface_name, network_type, sizeof(network_type));
    UPDATE_LABEL_SAFE(guider_ui.screen_label_45, label_network_buffer, network_type);
    // printf("Network type set to label_45: %s\n", network_type);
    
    // Create timer to check network status every 5 seconds
    lv_timer_t * network_timer = lv_timer_create(network_status_timer_cb, 5000, NULL);
}
void update_time(){
  time_t rawtime;
  struct tm * timeinfo;

  time(&rawtime);
  timeinfo = localtime(&rawtime);
  
  // Get 24-hour format first to determine AM/PM reliably
  int hour_24 = timeinfo->tm_hour;
  
  // Manually set AM/PM based on 24-hour time
  if (hour_24 >= 12) {
    strcpy(am_pm, "PM");
  } else {
    strcpy(am_pm, "AM");
  }
  
  // Convert to 12-hour format
  int hour_12 = hour_24 % 12;
  if (hour_12 == 0) hour_12 = 12; // Handle midnight and noon
  
  sprintf(hour, "%02d", hour_12);
  sprintf(minutes, "%02d", timeinfo->tm_min);
  sprintf(seconds, "%02d", timeinfo->tm_sec);
  
}


void set_screen_digital_clock_1(){
  update_time();
  screen_digital_clock_1_hour_value = atoi(hour);
  screen_digital_clock_1_min_value = atoi(minutes);
  screen_digital_clock_1_sec_value = atoi(seconds);
  strcpy(screen_digital_clock_1_meridiem, am_pm);
}

#include <sys/resource.h>
#include <time.h>

void check_lvgl_memory() {
    static long baseline = 0;
    static long previous = 0;
    static time_t start_time = 0;
    static int check_count = 0;
    
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    long current = usage.ru_maxrss;
    time_t now = time(NULL);
    
    if (baseline == 0) {
        baseline = current;
        previous = current;
        start_time = now;
        printf("\n=== Memory Tracking Started ===\n");
        printf("Baseline: %ld KB\n", baseline);
        printf("==============================\n\n");
        return;
    }
    
    check_count++;
    long growth = current - baseline;
    long delta = current - previous;  // Change since last check
    long elapsed_minutes = (now - start_time) / 60;
    
    printf("\n=== Memory Check #%d ===\n", check_count);
    printf("Current: %ld KB\n", current);
    printf("Total growth: %+ld KB\n", growth);
    printf("Change since last check: %+ld KB\n", delta);
    printf("Elapsed: %ld minutes\n", elapsed_minutes);
    
    // Determine status
    if (delta == 0) {
        printf("✅ STABLE - No change\n");
    } else if (delta > 0 && delta < 100) {
        printf("✅ STABLE - Minor fluctuation (+%ld KB)\n", delta);
    } else if (delta > 100) {
        printf("⚠ GROWING - Increased by %ld KB\n", delta);
    } else {
        printf("✅ STABLE - Decreased by %ld KB (GC)\n", -delta);
    }
    
    // Calculate growth rate
    if (elapsed_minutes > 0) {
        long growth_per_hour = (growth * 60) / elapsed_minutes;
        printf("Average growth rate: %ld KB/hour\n", growth_per_hour);
        
        if (growth_per_hour > 1024 && elapsed_minutes > 30) {
            printf("⚠ WARNING: Sustained leak detected!\n");
        } else if (elapsed_minutes > 10 && growth_per_hour < 100) {
            printf("✅ Memory stable - no leak detected\n");
        }
    }
    
    printf("====================\n\n");
    
    previous = current;  // Update for next check
}

// Rate limiter: Prevents processing same topic more than once per second
// Returns: true if message should be processed, false if should be skipped
static bool should_process_message(const char *topic) {
    // Skip rate limiting for critical topics that need immediate processing
    const char *critical_topics[] = {
        "everest_external/nodered/1/state/state_string",  // State changes are critical
        "everest_api/1/auth_consumer/auth_api/e2m/token_validation_status",  // Auth events
        NULL
    };
    
    // Check if this is a critical topic
    for (int i = 0; critical_topics[i] != NULL; i++) {
        if (strcmp(topic, critical_topics[i]) == 0) {
            return true;  // Always process critical topics
        }
    }
    
    // Rate limit all other topics
    typedef struct {
        char topic[128];
        time_t last_time;
    } TopicTimer;
    
    static TopicTimer timers[20] = {0};
    static int timer_count = 0;
    
    time_t now = time(NULL);
    
    // Find existing timer for this topic
    for (int i = 0; i < timer_count; i++) {
        if (strcmp(timers[i].topic, topic) == 0) {
            if (now == timers[i].last_time) {
                return false;  // Skip - already processed this second
            }
            timers[i].last_time = now;
            return true;  // Process - new second
        }
    }
    
    // New topic - add timer
    if (timer_count < 20) {
        strncpy(timers[timer_count].topic, topic, sizeof(timers[timer_count].topic) - 1);
        timers[timer_count].topic[sizeof(timers[timer_count].topic) - 1] = '\0';
        timers[timer_count].last_time = now;
        timer_count++;
    }
    
    return true;  // Process - first time or table full
}


int messageArrived(void *context, char *topic, int topicLen, MQTTClient_message *message) {

    static unsigned long msg_count = 0;
    static time_t last_rate_check = 0;
    static unsigned long last_msg_count = 0;
    static time_t last_mem_check = 0; 
    
    msg_count++;
    time_t now = time(NULL);

    // Rate limiting: Skip if same topic processed this second
    if (!should_process_message(topic)) {
        MQTTClient_freeMessage(&message);
        MQTTClient_free(topic);
        return 1;
    }

    if (now - last_rate_check >= 30) {
        unsigned long msgs_in_period = msg_count - last_msg_count;
        unsigned long msg_rate = msgs_in_period / 30;
        
        printf("MQTT Stats: %lu msg/s | Total: %lu | Reconnections: %lu\n", 
               msg_rate, msg_count, mqtt_reconnection_count);
        
        if (msg_rate > 100) {
            printf("WARNING: High message rate! Possible duplicate subscriptions!\n");
        }
        
        last_rate_check = now;
        last_msg_count = msg_count;
    }

      // ADD THESE 4 LINES:
    if (now - last_mem_check >= 60) {
        check_lvgl_memory();
        last_mem_check = now;
    }

    // Defensive checks
    if (message == NULL || topic == NULL || message->payload == NULL) {
        printf("ERROR: NULL message or topic received!\n");
        return 1;
    }
    
    if (message->payloadlen <= 0 || message->payloadlen > 10000) {
        printf("ERROR: Invalid payload length: %d\n", message->payloadlen);
        MQTTClient_freeMessage(&message);
        MQTTClient_free(topic);
        return 1;
    }

    // Update last message time
    last_mqtt_message_time = time(NULL);
    
    // Hide cont_4 when MQTT messages are coming (EVerest is running)
    lv_obj_add_flag(guider_ui.screen_cont_4, LV_OBJ_FLAG_HIDDEN);
    
    if (strcmp(topic,"everest_external/nodered/1/state/state_string") == 0){
       UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, (char *)message->payload);
       lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xdcd1e5), LV_PART_MAIN|LV_STATE_DEFAULT);
       lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_arial_30, 0);
      if (
          strcmp((char *)message->payload, "StoppingCharging") == 0 ||
          strcmp((char *)message->payload, "Finished") == 0 ||
          strcmp((char *)message->payload, "Idle") == 0
      ) {
          
          // Skip if already processed to prevent duplicate processing
          if (session_end_processed) {

              UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "Unplugged");
              UPDATE_LABEL_SAFE(guider_ui.screen_label_57, label_uid_buffer, "UID: NA");
              UPDATE_LABEL_SAFE(guider_ui.screen_label_58, label_card_type_buffer, "Type: NA");
              UPDATE_LABEL_SAFE(guider_ui.screen_label_59, label_card_status_buffer, "Status: NA");
              lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
              MQTTClient_freeMessage(&message);
              MQTTClient_free(topic);
              return 1;
          }
          
          // Mark as processed immediately
          session_end_processed = true;
          
          // Get current system time
          time_t rawtime;
          struct tm * timeinfo;
          time(&rawtime);
          timeinfo = localtime(&rawtime);
          
          active_session = false;
          start_time_captured = false;  // Keep this here
          // pause_time_captured will be reset later
          
          lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xdcd1e5), LV_PART_MAIN|LV_STATE_DEFAULT);
          lv_img_set_src(guider_ui.screen_img_2, &_Car_Unplugged_0_alpha_1277x797);
          
          // migrated_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_
          UPDATE_LABEL_SAFE(guider_ui.screen_label_10, label_time_buffer, "--:--:--");
          UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "Unplugged");
          lv_obj_add_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
          // Reset NFC Card UID and Type (always, regardless of session state)
          UPDATE_LABEL_SAFE(guider_ui.screen_label_57, label_uid_buffer, "UID: NA");
          UPDATE_LABEL_SAFE(guider_ui.screen_label_58, label_card_type_buffer, "Type: NA");
          UPDATE_LABEL_SAFE(guider_ui.screen_label_59, label_card_status_buffer, "Status: NA");
          lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
          char string_time_out[20];
          char diff_time[20];

      // Use pause time as end time if session was paused, otherwise use current time
      if (pause_time_captured) {
          endTime = pauseTime;

      } else {
          set_screen_digital_clock_1();
          endTime.hours = atoi(hour);
          endTime.minutes = atoi(minutes);
          endTime.seconds = atoi(seconds);
          endTime.ampm = (strcmp(am_pm, "AM") == 0) ? 'A' : 'P';
   
      }
  
      // Calculate duration
      startTimeInSeconds = timeToSeconds(startTime);
  endTimeInSeconds = timeToSeconds(endTime);
  
  diffInSeconds = endTimeInSeconds - startTimeInSeconds;
  if (diffInSeconds < 0){
    diffInSeconds += 86400;
  }
  diffTime = secondsToTime(diffInSeconds);
  
  if (diffTime.hours == 12){
    diffTime.hours = 00;
  }

  // Format end time string
  snprintf(string_time_out, sizeof(string_time_out), "%02d:%02d:%02d %s", 
           endTime.hours, endTime.minutes, endTime.seconds,
           (endTime.ampm == 'A') ? "AM" : "PM");
  snprintf(diff_time, sizeof(diff_time), "%02d:%02d:%02d", 
           diffTime.hours, diffTime.minutes, diffTime.seconds);

  UPDATE_LABEL_SAFE(guider_ui.screen_label_30, label_end_time_buffer, string_time_out);
  UPDATE_LABEL_SAFE(guider_ui.screen_label_31, label_duration_buffer, diff_time);
          if (is_session_started){
            lv_obj_clear_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
            battery_level = 20.0;
            totalKWattHr = 0.000;
            mqtt_power_kw = 0.0f;
            mqtt_energy_kwh = 0.0f;
            UPDATE_LABEL_SAFE(guider_ui.screen_label_38, label_battery_buffer, "20.0");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_19, label_battery_buffer, "20.0");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_3, label_energy_buffer, "0.0kWh");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_11, label_duration_buffer, "--:--:--");
            lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, 0);
            UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, "0");
            lv_bar_set_value(guider_ui.screen_bar_2, 20, LV_ANIM_OFF);
            UPDATE_LABEL_SAFE(guider_ui.screen_label_57, label_uid_buffer, "UID: NA");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_58, label_card_type_buffer, "Type: NA");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_59, label_card_status_buffer, "Status: NA");
            lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);

            is_session_started = false;
            printf("Session values reset (is_session_started was true)\n");
          }

          pause_time_captured = false;
        // migrated_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_
      }
      // Capture pause time (handles both manual and automatic pause)
      if (strcmp((char *)message->payload, "EVSE Paused") == 0) {
          set_screen_digital_clock_1();
          pauseTime.hours = atoi(hour);
          pauseTime.minutes = atoi(minutes);
          pauseTime.seconds = atoi(seconds);
          pauseTime.ampm = (strcmp(am_pm, "AM") == 0) ? 'A' : 'P';
          pause_time_captured = true;
      }

      // Existing grouped condition (keep as is)
      if (
          strcmp((char *)message->payload, "Wait for Auth") == 0 ||
          strcmp((char *)message->payload, "EVSE Paused") == 0 ||
          strcmp((char *)message->payload, "Wait for energy") == 0
          // strcmp((char *)message->payload, "PrepareCharging") == 0
      ) {
          active_session = false;
          lv_img_set_src(guider_ui.screen_img_2, &_Car_Unplugged_alpha_1280x800);
          lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xdcd1e5), LV_PART_MAIN|LV_STATE_DEFAULT);
      }

      if (
          strcmp((char *)message->payload, "Wait for Auth") == 0
      ) {
          active_session = false;
          lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_arial_30, 0);
          UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "Plugged in");
          sleep(1);
          UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "Wait for Auth");
          is_new_session = true;	
      }
      if (
          strcmp((char *)message->payload, "Charging") == 0
      ) {
          active_session = true;
          lv_img_set_src(guider_ui.screen_img_2, &_Car_plugged_alpha_1280x800);
          lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xd0ff00), LV_PART_MAIN|LV_STATE_DEFAULT);
          
          // ADD THIS ENTIRE BLOCK
          if (!start_time_captured && is_session_started) {
              char string_time[20];
              set_screen_digital_clock_1();
              
              startTime.hours = atoi(hour);
              startTime.minutes = atoi(minutes);
              startTime.seconds = atoi(seconds); 
              startTime.ampm = (strcmp(am_pm, "AM") == 0) ? 'A' : 'P';
              
              snprintf(string_time, sizeof(string_time), "%s:%s:%s %s", hour, minutes, seconds, am_pm);
              
              UPDATE_LABEL_SAFE(guider_ui.screen_label_10, label_time_buffer, string_time);
              UPDATE_LABEL_SAFE(guider_ui.screen_label_29, label_time_buffer, string_time);
              
              start_time_captured = true;
            //   printf("Start time captured at Charging state: %s\n", string_time);
          }
      }      
      if ((strcmp((char *)message->payload,"PrepareCharging") == 0) && (is_new_session)){
        lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_arial_30, 0);
        UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "Authenticating...");
        char string_time[20];
        set_screen_digital_clock_1();
        is_session_started = true;
        active_session = false;
        session_end_processed = false;  // ADD THIS LINE - Reset for new session
        sleep(2);

        // lv_obj_clear_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
        // lv_obj_clear_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
        // lv_obj_clear_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
        // lv_obj_clear_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
      }

      if (strcmp((char *)message->payload,"Idle") == 0){
        // UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "Unplugged");
        // char string_time_out[20];
        // char diff_time[20];

        // set_screen_digital_clock_1();
        // endTime.hours = atoi(hour);
        // endTime.minutes = atoi(minutes);
        // endTime.seconds = atoi(seconds); 
        // endTime.ampm = strcmp(am_pm,"AM") ? 'A' : 'p';

        // startTimeInSeconds = timeToSeconds(startTime);
        // endTimeInSeconds = timeToSeconds(endTime);

        // diffInSeconds = endTimeInSeconds - startTimeInSeconds;
        // if (diffInSeconds < 0){
        //   diffInSeconds +=86400;
        // }
        // diffTime = secondsToTime(diffInSeconds);

        // if (diffTime.hours == 12){
        //   diffTime.hours = 00;
        // }
        
        // snprintf(string_time_out, sizeof(string_time_out), "%s:%s:%s %s", hour, minutes, seconds, am_pm);
        // snprintf(diff_time, sizeof(diff_time), "%02d:%02d:%02d", diffTime.hours, diffTime.minutes, diffTime.seconds);
        // UPDATE_LABEL_SAFE(guider_ui.screen_label_30, label_end_time_buffer, string_time_out);
        // UPDATE_LABEL_SAFE(guider_ui.screen_label_31, label_duration_buffer, diff_time);
        // if (is_session_started){
        //   lv_obj_clear_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
        //   is_session_started = false;
        // }
      }
      
    } else if (strcmp(topic,"everest_external/nodered/1/state/temperature") == 0){
      // UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, topic);
      char payload_copy[256];
      int len = message->payloadlen < 255 ? message->payloadlen : 255;
      memcpy(payload_copy, message->payload, len);
      payload_copy[len] = '\0';
      
      char *delim = ".";
      char before_dot[20];
      char *token;
      token = strtok(payload_copy, delim);  // ✅ Modify copy, not original
      
       if (token != NULL) {
            UPDATE_LABEL_SAFE(guider_ui.screen_label_4, label_temp_buffer, token);
        }
    } else if (strcmp(topic,"everest_external/nodered/1/powermeter/totalKw") == 0){
      // UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, topic);
      //move to increare_batery_level 
      // lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, atoi(message->payload));
      // lv_label_set_text_fmt(gui->speed_label_digit, "%"LV_PRId32, speed);
      //UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, (char *)message->payload);
    //   mqtt_power_kw = atof((char *)message->payload);
    //   printf("Received totalKw: %.2f\n", mqtt_power_kw);
      //move to increare_batery_level UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, (char *)message->payload);

       int result = system("ping -c 1 8.8.8.8 -W 2 2>/dev/null 1>/dev/null");
      //move to increare_batery_level 
      //UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, (char *)message->payload);
    //   mqtt_power_kw = atof((char *)message->payload);
    //   printf("Received totalKw: %.2f\n", mqtt_power_kw);

      // Network connectivity check and icon update
      if (result == 0) {
        //   printf("Internet connection is available.\n");
          lv_obj_add_flag(guider_ui.screen_label_13, LV_OBJ_FLAG_HIDDEN);
          // lv_obj_add_flag(guider_ui.screen_label_15, LV_OBJ_FLAG_HIDDEN);
          lv_obj_clear_flag(guider_ui.screen_img_6, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_img_17, LV_OBJ_FLAG_HIDDEN);
        
      } else {
          lv_obj_clear_flag(guider_ui.screen_label_13, LV_OBJ_FLAG_HIDDEN);
          // lv_obj_clear_flag(guider_ui.screen_label_15, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_img_6, LV_OBJ_FLAG_HIDDEN);
          lv_obj_clear_flag(guider_ui.screen_img_17, LV_OBJ_FLAG_HIDDEN);
        //   printf("Internet connection is not available.\n");
      } 
    increase_battery_level();


    }else if (strcmp(topic,"everest_api/ocpp/var/connection_status") == 0){
    //   printf("Received CSMS connection status: %s, value: %.*s\n", topic, message->payloadlen, (char *)message->payload);
      
      // Handle connection status values: "connected", "disconnected", "unknown"
      if (strcmp((char *)message->payload, "connected") == 0) {
          // CSMS connected - show green/connected icon (img_11)
          lv_obj_clear_flag(guider_ui.screen_img_11, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_img_16, LV_OBJ_FLAG_HIDDEN);
        //   printf("CSMS Status: Connected ✓\n");
          
      } else if (strcmp((char *)message->payload, "disconnected") == 0) {
          // CSMS disconnected - show red/disconnected icon (img_16)
          lv_obj_add_flag(guider_ui.screen_img_11, LV_OBJ_FLAG_HIDDEN);
          lv_obj_clear_flag(guider_ui.screen_img_16, LV_OBJ_FLAG_HIDDEN);
        //   printf("CSMS Status: Disconnected ✗\n");
          
      } else if (strcmp((char *)message->payload, "unknown") == 0) {
          // CSMS status unknown - treat as disconnected
          lv_obj_add_flag(guider_ui.screen_img_11, LV_OBJ_FLAG_HIDDEN);
          lv_obj_clear_flag(guider_ui.screen_img_16, LV_OBJ_FLAG_HIDDEN);
        //   printf("CSMS Status: Unknown (treated as disconnected)\n");
          
      } else {
          // Unexpected value - default to disconnected
          lv_obj_add_flag(guider_ui.screen_img_11, LV_OBJ_FLAG_HIDDEN);
          lv_obj_clear_flag(guider_ui.screen_img_16, LV_OBJ_FLAG_HIDDEN);
          printf("CSMS Status: Unexpected '%s' (treated as disconnected)\n", 
                 (char *)message->payload);
      }
        
    } else if (strcmp(topic,"everest_external/nodered/1/powermeter/totalKWattHr") == 0){
      // will uncomment with actual values
      // UPDATE_LABEL_SAFE(guider_ui.screen_label_3, label_energy_buffer, (char *)message->payload);
      // strcpy(final_energy,(char *)message->payload);
      mqtt_energy_kwh = atof((char *)message->payload);
      strcpy(final_energy, (char *)message->payload);
    //   printf("Received totalKWattHr: %.3f\n", mqtt_energy_kwh);

    //   printf("this is blank");
      // will uncomment with actual values
    } else if (strcmp(topic, "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/evse_id") == 0) {
      char evse_id_display[128];
    
      // Debug: Show raw payload
      printf("EVSE ID topic received, payload length: %d\n", message->payloadlen);
      if (message->payloadlen > 0 && message->payload != NULL) {
          printf("Raw payload: '%.*s'\n", message->payloadlen, (char *)message->payload);
      }
      
      // Check if payload is valid
      if (message->payloadlen > 0 && message->payloadlen < 256 && message->payload != NULL) {
          char *payload_str = (char *)message->payload;
          
          // Copy payload to safe buffer
          char payload_copy[256];
          int copy_len = message->payloadlen < 255 ? message->payloadlen : 255;
          memcpy(payload_copy, payload_str, copy_len);
          payload_copy[copy_len] = '\0';
          
          // Remove quotes and whitespace
          char evse_id[128] = {0};
          int idx = 0;
          
          for (int i = 0; i < copy_len && idx < 127; i++) {
              char c = payload_copy[i];
              // Skip quotes, whitespace, newlines, carriage returns
              if (c != '"' && c != '\'' && c != ' ' && c != '\t' && 
                  c != '\n' && c != '\r' && c != '\0') {
                  evse_id[idx++] = c;
              }
          }
          evse_id[idx] = '\0';
          
          // Validate EVSE ID format (should contain at least one '*' separator)
          // Format: Country*Operator*ID*Connector (e.g., "RO*NXP*E1234567*1")
          bool has_separator = (strchr(evse_id, '*') != NULL);
          
          // Check if we got a valid EVSE ID
          if (strlen(evse_id) > 0 && has_separator) {
              snprintf(label_evse_id_buffer, sizeof(label_evse_id_buffer), "EVSE ID: %s", evse_id);
              lv_label_set_text_static(guider_ui.screen_label_43, label_evse_id_buffer);
              printf("✓ EVSE ID set: %s\n", evse_id);
          } else if (strlen(evse_id) > 0) {
              // Got data but doesn't look like valid EVSE ID format
              snprintf(evse_id_display, sizeof(evse_id_display), "EVSE ID: %s", evse_id);
              UPDATE_LABEL_SAFE(guider_ui.screen_label_43, label_evse_id_buffer, evse_id_display);
              printf("⚠ EVSE ID set (non-standard format): %s\n", evse_id);
          } else {
              UPDATE_LABEL_SAFE(guider_ui.screen_label_43, label_evse_id_buffer, "EVSE ID: NA");
              printf("✗ EVSE ID: NA (empty after parsing)\n");
          }
      } else {
          UPDATE_LABEL_SAFE(guider_ui.screen_label_43, label_evse_id_buffer, "EVSE ID: NA");
          printf("✗ EVSE ID: NA (invalid payload - len=%d, ptr=%p)\n", 
                message->payloadlen, message->payload);
      }
    
    } else if (strcmp(topic, "everest_external/nodered/1/ev/ev_id") == 0) {
      char ev_id_display[128];
      
      // Check if payload is empty or null
      if (message->payloadlen > 0 && message->payload != NULL) {
          snprintf(ev_id_display, sizeof(ev_id_display), "EV ID: %s", (char *)message->payload);
          UPDATE_LABEL_SAFE(guider_ui.screen_label_44, label_ev_id_buffer, ev_id_display);
          printf("EV ID: %s\n", (char *)message->payload);
      } else {
          UPDATE_LABEL_SAFE(guider_ui.screen_label_44, label_ev_id_buffer, "EV ID: NA");
          printf("EV ID: NA (empty payload)\n");
    }
    
    } else if (strcmp(topic, "everest_external/nodered/1/ev/battery_level") == 0) {
    // Store MQTT battery level
    if (message->payloadlen > 0 && message->payload != NULL) {
        mqtt_battery_level = atof((char *)message->payload);
        printf("Battery Level from MQTT: %.1f\n", mqtt_battery_level);
    } else {
        mqtt_battery_level = -1.0f;  // Reset to no data
        printf("Battery Level: No data (empty payload)\n");
    }
    
  } else if (strcmp(topic, "everest_external/nodered/1/iso15118/mode") == 0) {
    char iso_mode_display[32];
      
    if (message->payloadlen > 0 && message->payload != NULL) {
        char mode = ((char *)message->payload)[0];  // Get first character (A, B, C, D, E, or F)
          
        // Validate mode is A-F
        if ((mode >= 'A' && mode <= 'F') || (mode >= 'a' && mode <= 'f')) {
            snprintf(label_iso_mode_buffer, sizeof(label_iso_mode_buffer), "ISO Mode: %c", toupper(mode));
            lv_label_set_text_static(guider_ui.screen_label_52, label_iso_mode_buffer);
            printf("ISO 15118 Mode: %c\n", toupper(mode));
        } else {
            UPDATE_LABEL_SAFE(guider_ui.screen_label_52, label_iso_mode_buffer, "ISO Mode: NA");
            printf("ISO 15118 Mode: Invalid mode '%s'\n", (char *)message->payload);
        }
    } else {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_52, label_iso_mode_buffer, "ISO Mode: NA");
        printf("ISO 15118 Mode: NA (empty payload)\n");
    }
    
  } else if (strcmp(topic, "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/selected_protocol") == 0) {
    char protocol_display[64];
    
    if (message->payloadlen > 0 && message->payload != NULL) {
        char *payload_str = (char *)message->payload;
        
        // The payload is a simple string value like "IEC61851-1" or "Unknown"
        // Remove quotes if present
        char protocol[64] = {0};
        int idx = 0;
        
        for (int i = 0; i < message->payloadlen && i < 63; i++) {
            char c = payload_str[i];
            // Skip quotes
            if (c != '"' && c != '\0') {
                protocol[idx++] = c;
            }
        }
        protocol[idx] = '\0';
        
        // Check for known protocols
        if (strcasecmp(protocol, "Unknown") == 0) {
            snprintf(label_protocol_buffer, sizeof(label_protocol_buffer), "Protocol: Unknown");
        } else if (strstr(protocol, "15118-2") != NULL || 
                   strstr(protocol, "15118_2") != NULL ||
                   strcasecmp(protocol, "ISO15118-2") == 0 ||
                   strcasecmp(protocol, "ISO 15118-2") == 0) {
            snprintf(label_protocol_buffer, sizeof(label_protocol_buffer), "Protocol: ISO 15118-2");
        } else if (strstr(protocol, "15118-20") != NULL || 
                   strstr(protocol, "15118_20") != NULL ||
                   strcasecmp(protocol, "ISO15118-20") == 0 ||
                   strcasecmp(protocol, "ISO 15118-20") == 0) {
            snprintf(label_protocol_buffer, sizeof(label_protocol_buffer), "Protocol: ISO 15118-20");
        } else if (strcasecmp(protocol, "IEC61851-1") == 0 ||
                   strcasecmp(protocol, "IEC 61851-1") == 0 ||
                   strcasecmp(protocol, "IEC61851") == 0 ||
                   strcasecmp(protocol, "Basic") == 0 ||
                   strstr(protocol, "61851") != NULL) {
            snprintf(label_protocol_buffer, sizeof(label_protocol_buffer), "Protocol: Basic");
        } else if (strlen(protocol) > 0) {
            // Display the raw protocol value if not empty and unknown
            snprintf(label_protocol_buffer, sizeof(label_protocol_buffer), "Protocol: %s", protocol);
        } else {
            snprintf(label_protocol_buffer, sizeof(label_protocol_buffer), "Protocol: NA");
        }
        
        lv_label_set_text_static(guider_ui.screen_label_53, label_protocol_buffer);;
        printf("Selected Protocol: %s\n", protocol);
    } else {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_53, label_protocol_buffer, "Protocol: NA");
        printf("Selected Protocol: NA (empty payload)\n");
    }
  } else if (strcmp(topic, "everest_external/nodered/1/iso15118/voltage") == 0) {
    char voltage_display[32];
      
    if (message->payloadlen > 0 && message->payload != NULL) {
        float voltage = atof((char *)message->payload);
          
        // Validate voltage range (0-1000V typical for EV charging)
        if (voltage >= 0.0f && voltage <= 1000.0f) {
            // Check if voltage is a whole number
            if (voltage == (int)voltage) {
                // Display as integer (e.g., "Voltage: 400 V")
                snprintf(label_voltage_buffer, sizeof(label_voltage_buffer), "Voltage: %d V", (int)voltage);
            } else {
                // Display with 1 decimal place (e.g., "Voltage: 400.5 V")
                snprintf(label_voltage_buffer, sizeof(label_voltage_buffer), "Voltage: %.1f V", voltage);
            }
            lv_label_set_text_static(guider_ui.screen_label_54, label_voltage_buffer);
            printf("ISO 15118 Voltage: %.1f V\n", voltage);
        } else {
            // Out of range
            UPDATE_LABEL_SAFE(guider_ui.screen_label_54, label_voltage_buffer, "Voltage: NA");
            printf("ISO 15118 Voltage: Out of range (%.1f V)\n", voltage);
        }
    } else {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_54, label_voltage_buffer, "Voltage: NA");
        printf("ISO 15118 Voltage: NA (empty payload)\n");
    }
  
  } else if (strcmp(topic, "everest_external/nodered/1/iso15118/direction") == 0) {
    char direction_display[32];
      
    if (message->payloadlen > 0 && message->payload != NULL) {
        char *direction = (char *)message->payload;
          
        // Check for G2V (Grid to Vehicle - Charging)
        if (strcasecmp(direction, "G2V") == 0 ||
            strcasecmp(direction, "Grid2Vehicle") == 0 ||
            strcasecmp(direction, "GridToVehicle") == 0 ||
            strcasecmp(direction, "Grid to Vehicle") == 0 ||
            strstr(direction, "G2V") != NULL ||
            strstr(direction, "g2v") != NULL) {
            snprintf(label_direction_buffer, sizeof(label_direction_buffer), "Direction: G2V");
            lv_label_set_text_static(guider_ui.screen_label_55, label_direction_buffer);
            printf("ISO 15118 Direction: G2V (Grid to Vehicle - Charging)\n");
        }
        // Check for V2G (Vehicle to Grid - Discharging)
        else if (strcasecmp(direction, "V2G") == 0 ||
                      strcasecmp(direction, "Vehicle2Grid") == 0 ||
                      strcasecmp(direction, "VehicleToGrid") == 0 ||
                      strcasecmp(direction, "Vehicle to Grid") == 0 ||
                      strstr(direction, "V2G") != NULL ||
                      strstr(direction, "v2g") != NULL) {
            snprintf(label_direction_buffer, sizeof(label_direction_buffer), "Direction: V2G");
            lv_label_set_text_static(guider_ui.screen_label_55, label_direction_buffer);
            printf("ISO 15118 Direction: V2G (Vehicle to Grid - Discharging)\n");
        }
        // Unknown or invalid direction
        else {
            UPDATE_LABEL_SAFE(guider_ui.screen_label_55, label_direction_buffer, "Direction: NA");
            printf("ISO 15118 Direction: Unknown (%s)\n", direction);
        }
    } else {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_55, label_direction_buffer, "Direction: NA");
        printf("ISO 15118 Direction: NA (empty payload)\n");
    }
  
  } else if (strcmp(topic, "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/hw_capabilities") == 0) {
    char connection_display[32];
        // Validate payload
    if (message->payloadlen <= 0 || message->payload == NULL) {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_56, label_sigboard_buffer, "Sigboard: NA");
        MQTTClient_freeMessage(&message);
        MQTTClient_free(topic);
        return 1;
    }
    
    char *payload_str = (char *)message->payload;
    char *connector_start = strstr(payload_str, "\"connector_type\":");
    
    // Check if connector_type field exists
    if (connector_start == NULL) {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_56, label_sigboard_buffer, "Sigboard: NA");
        MQTTClient_freeMessage(&message);
        MQTTClient_free(topic);
        return 1;
    }

    // Skip past "connector_type": and whitespace/quotes
    connector_start += 17;
    while (*connector_start == ' ' || *connector_start == '\t' || *connector_start == '"') {
        connector_start++;
    }
    
    // Find closing quote
    char *connector_end = strchr(connector_start, '"');
    if (connector_end == NULL || (connector_end - connector_start) <= 0) {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_56, label_sigboard_buffer, "Sigboard: NA");
        MQTTClient_freeMessage(&message);
        MQTTClient_free(topic);
        return 1;
    }

    // Extract connector type string
    int connector_len = connector_end - connector_start;
    char connector_type[64];
    strncpy(connector_type, connector_start, connector_len);
    connector_type[connector_len] = '\0';
    
    // Map connector type to display string
    const char *display_text = NULL;
    
    if (strcasestr(connector_type, "IEC62196Type2Cable") || strcasestr(connector_type, "Type2Cable")) {
        display_text = "Sigboard: Type2 Cable";
    } else if (strcasestr(connector_type, "IEC62196Type2Socket") || strcasestr(connector_type, "Type2Socket")) {
        display_text = "Sigboard: Type2 Socket";
    } else if (strcasestr(connector_type, "Type1")) {
        display_text = "Sigboard: Type1";
    } else if (strcasestr(connector_type, "CCS")) {
        display_text = "Sigboard: CCS";
    } else if (strcasestr(connector_type, "CHAdeMO")) {
        display_text = "Sigboard: CHAdeMO";
    } else {
        // Unknown connector - display raw value
        snprintf(label_sigboard_buffer, sizeof(label_sigboard_buffer), "Sigboard: %s", connector_type);
        display_text = label_sigboard_buffer;
    }
    // Update label
    if (display_text != label_sigboard_buffer) {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_56, label_sigboard_buffer, display_text);
    } else {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_56, label_sigboard_buffer, "Sigboard: NA");
    }
  
  } else if (strcmp(topic, "everest_api/1/auth_consumer/auth_api/e2m/token_validation_status") == 0) {
      char *payload_str = (char *)message->payload;
    char uid_display[64];
    char type_display[64];
    char status_display[64];
    
    // Find "value" field in id_token for UID
    char *value_start = strstr(payload_str, "\"value\":");
    
    if (value_start != NULL) {
        value_start += 8;  // Skip past "value":
        
        // Skip whitespace and opening quote
        while (*value_start == ' ' || *value_start == '\t' || *value_start == '"') {
            value_start++;
        }
        
        // Find closing quote
        char *value_end = strchr(value_start, '"');
        
        if (value_end != NULL && (value_end - value_start) > 0) {
            int uid_len = value_end - value_start;
            char uid_raw[64];
            strncpy(uid_raw, value_start, uid_len);
            uid_raw[uid_len] = '\0';
            
            // Clean: keep only hex characters
            char uid_clean[64] = {0};
            int clean_idx = 0;
            for (int i = 0; i < uid_len && clean_idx < 63; i++) {
                char c = uid_raw[i];
                if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
                    uid_clean[clean_idx++] = toupper(c);
                }
            }
            
            int clean_len = strlen(uid_clean);
            
            // Format with colons if valid length (4, 7, or 10 bytes)
            if (clean_len == 8 || clean_len == 14 || clean_len == 20) {
                char uid_formatted[32] = {0};
                int fmt_idx = 0;
                for (int i = 0; i < clean_len; i += 2) {
                    if (i > 0) uid_formatted[fmt_idx++] = ':';
                    uid_formatted[fmt_idx++] = uid_clean[i];
                    uid_formatted[fmt_idx++] = uid_clean[i + 1];
                }
                snprintf(label_uid_buffer, sizeof(label_uid_buffer), "UID: %s", uid_formatted);
            } else {
                snprintf(label_uid_buffer, sizeof(label_uid_buffer), "UID: NA");
            }
        } else {
            snprintf(label_uid_buffer, sizeof(label_uid_buffer), "UID: NA");
        }
    } else {
        snprintf(label_uid_buffer, sizeof(label_uid_buffer), "UID: NA");
    }
    
    lv_label_set_text_static(guider_ui.screen_label_57, label_uid_buffer);
    
    // Find "type" field in id_token for Card Type
    char *type_start = strstr(payload_str, "\"type\":");
    
    if (type_start != NULL) {
        type_start += 7;  // Skip past "type":
        
        // Skip whitespace and opening quote
        while (*type_start == ' ' || *type_start == '\t' || *type_start == '"') {
            type_start++;
        }
        
        // Find closing quote
        char *type_end = strchr(type_start, '"');
        
        if (type_end != NULL && (type_end - type_start) > 0) {
            int type_len = type_end - type_start;
            char card_type[64];
            strncpy(card_type, type_start, type_len);
            card_type[type_len] = '\0';
            
            // Check for known card types
            if (strcasecmp(card_type, "Local") == 0) {
                snprintf(label_card_type_buffer, sizeof(label_card_type_buffer), "Type: Local");
            } else if (strcasecmp(card_type, "ISO14443") == 0 || 
                       strcasestr(card_type, "14443") != NULL) {
                snprintf(label_card_type_buffer, sizeof(label_card_type_buffer), "Type: ISO14443");
            } else if (strcasestr(card_type, "MIFARE") != NULL) {
                snprintf(label_card_type_buffer, sizeof(label_card_type_buffer), "Type: MIFARE");
            } else if (strcasestr(card_type, "NTAG") != NULL) {
                snprintf(label_card_type_buffer, sizeof(label_card_type_buffer), "Type: NTAG");
            } else if (strcasecmp(card_type, "Central") == 0) {
                snprintf(label_card_type_buffer, sizeof(label_card_type_buffer), "Type: Central");
            } else if (strcasecmp(card_type, "eMAID") == 0) {
                snprintf(label_card_type_buffer, sizeof(label_card_type_buffer), "Type: eMAID");
            } else if (strcasecmp(card_type, "ISO15693") == 0 || 
                       strcasestr(card_type, "15693") != NULL) {
                snprintf(label_card_type_buffer, sizeof(label_card_type_buffer), "Type: ISO15693");
            } else {
                // Display the raw type value if unknown
                snprintf(label_card_type_buffer, sizeof(label_card_type_buffer), "Type: %s", card_type);
            }
        } else {
            snprintf(label_card_type_buffer, sizeof(label_card_type_buffer), "Type: NA");
        }
    } else {
        snprintf(label_card_type_buffer, sizeof(label_card_type_buffer), "Type: NA");
    }
    
    lv_label_set_text_static(guider_ui.screen_label_58, label_card_type_buffer);
    
    // Find "status" field for Card Status
    char *status_start = strstr(payload_str, "\"status\":");
    
    if (status_start != NULL) {
        status_start += 9;  // Skip past "status":
        
        // Skip whitespace and opening quote
        while (*status_start == ' ' || *status_start == '\t' || *status_start == '"') {
            status_start++;
        }
        
        // Find closing quote
        char *status_end = strchr(status_start, '"');
        
        if (status_end != NULL && (status_end - status_start) > 0) {
            int status_len = status_end - status_start;
            char card_status[64];
            strncpy(card_status, status_start, status_len);
            card_status[status_len] = '\0';
            
            // Check for Accepted/Authorized status
            if (strcasecmp(card_status, "Accepted") == 0 ||
                strcasecmp(card_status, "Authorized") == 0 ||
                strcasecmp(card_status, "UsedToStart") == 0 ||
                strcasecmp(card_status, "Valid") == 0 ||
                strcasecmp(card_status, "OK") == 0) {
                snprintf(label_card_status_buffer, sizeof(label_card_status_buffer), "Status: Accepted");
                lv_label_set_text_static(guider_ui.screen_label_59, label_card_status_buffer);
                // Set text color to green
                lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0x00FF00), LV_PART_MAIN|LV_STATE_DEFAULT);
            }
            // Check for Rejected/Denied status
            else if (strcasecmp(card_status, "Rejected") == 0 ||
                     strcasecmp(card_status, "Denied") == 0 ||
                     strcasecmp(card_status, "Invalid") == 0 ||
                     strcasecmp(card_status, "Blocked") == 0 ||
                     strcasecmp(card_status, "Failed") == 0) {
                snprintf(label_card_status_buffer, sizeof(label_card_status_buffer), "Status: Rejected");
                lv_label_set_text_static(guider_ui.screen_label_59, label_card_status_buffer);
                // Set text color to red
                lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xFF0000), LV_PART_MAIN|LV_STATE_DEFAULT);
            }
            // Unknown status - display as-is
            else {
                snprintf(label_card_status_buffer, sizeof(label_card_status_buffer), "Status: %s", card_status);
                lv_label_set_text_static(guider_ui.screen_label_59, label_card_status_buffer);
                // Set text color to default gray/white
                lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
            }
        } else {
            snprintf(label_card_status_buffer, sizeof(label_card_status_buffer), "Status: NA");
            lv_label_set_text_static(guider_ui.screen_label_59, label_card_status_buffer);
            lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
        }
    } else {
        snprintf(label_card_status_buffer, sizeof(label_card_status_buffer), "Status: NA");
        lv_label_set_text_static(guider_ui.screen_label_59, label_card_status_buffer);
        lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
    }

  } else if (strcmp(topic, "everest_api/evse_manager_1/var/powermeter") == 0) {
        // printf("Received powermeter data: %.*s\n", message->payloadlen, (char *)message->payload);
        
        // Parse L1 current using string search
        char *payload_str = (char *)message->payload;
        
        // First, find the "current_A" section
        char *current_a_start = strstr(payload_str, "\"current_A\":");
        
        if (current_a_start != NULL) {
            // Now find L1 within current_A section (not voltage_V section)
            char *l1_start = strstr(current_a_start, "\"L1\":");
            
            if (l1_start != NULL) {
                // Move pointer past "L1":
                l1_start += 5;
                
                // Skip whitespace
                while (*l1_start == ' ' || *l1_start == '\t') {
                    l1_start++;
                }
                
                // Parse the float value
                float current_l1 = atof(l1_start);
                char current_display[32];
                
                // Format: "24.5 A" with 1 decimal place
                snprintf(label_current_buffer, sizeof(label_current_buffer), "%.1f A", current_l1);
                
                // Update label_60
                lv_label_set_text_static(guider_ui.screen_label_60, label_current_buffer);
                // printf("Current L1 updated: %s\n", current_display);
                
                // Future: Add L2, L3, N handling here with else if blocks
                
            } else {
                printf("Warning: L1 value not found in current_A section\n");
            }
        } else {
            printf("Warning: current_A section not found in powermeter data\n");
        }
    }
  
  MQTTClient_freeMessage(&message);
  MQTTClient_free(topic);
  return 1;
}


// Helper function to unsubscribe from all MQTT topics
// Returns: number of successful unsubscriptions
int unsubscribe_from_mqtt_topics() {
    int success_count = 0;
    
    printf("Unsubscribing from %d MQTT topics...\n", MQTT_TOPICS_COUNT);
    
    for (int i = 0; i < MQTT_TOPICS_COUNT; i++) {
        int rc = MQTTClient_unsubscribe(client, MQTT_TOPICS[i]);
        if (rc == MQTTCLIENT_SUCCESS) {
            success_count++;
        } else {
            printf("  ✗ Failed to unsubscribe from %s: %d\n", MQTT_TOPICS[i], rc);
        }
    }
    
    printf("Successfully unsubscribed from %d/%d topics\n", success_count, MQTT_TOPICS_COUNT);
    mqtt_topics_subscribed = false;
    
    return success_count;
}

int subscribe_to_mqtt_topics() {
    // Safety check: prevent duplicate subscriptions
    if (mqtt_topics_subscribed) {
        printf("⚠ WARNING: Topics already subscribed! Unsubscribing first...\n");
        unsubscribe_from_mqtt_topics();
        mqtt_topics_subscribed = false;
    }
    
    int success_count = 0;
    
    printf("Subscribing to %d MQTT topics...\n", MQTT_TOPICS_COUNT);
    
    for (int i = 0; i < MQTT_TOPICS_COUNT; i++) {
        int rc = MQTTClient_subscribe(client, MQTT_TOPICS[i], QOS);
        if (rc == MQTTCLIENT_SUCCESS) {
            success_count++;
        } else {
            printf("  ✗ Failed to subscribe to %s: %d\n", MQTT_TOPICS[i], rc);
        }
    }
    
    printf("Successfully subscribed to %d/%d topics\n", success_count, MQTT_TOPICS_COUNT);
    
    if (success_count == MQTT_TOPICS_COUNT) {
        mqtt_topics_subscribed = true;
    }
    
    return success_count;
}

void get_mqtt_state_for_evse()
{
  
  // lv_label_set_text(guider_ui.pageStatic_label_1, PAYLOAD);
  // MQTTClient_create(&client, ADDRESS, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL); 
  // MQTTClient_setCallbacks(client, NULL, NULL, messageArrived, NULL);

  MQTTClient_create(&client, ADDRESS, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL); 
  MQTTClient_setCallbacks(client, NULL, connectionLost, messageArrived, NULL);

  MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer; 
  conn_opts.connectTimeout = 30;
  conn_opts.keepAliveInterval = 60;
  conn_opts.retryInterval = 5;
  conn_opts.cleansession = 1;

  int retry_count = 0;
  int rc;
  // Retry connecting 10 times in case of failure
  while (retry_count < 10) {
    rc = MQTTClient_connect(client, &conn_opts);
    if (rc == MQTTCLIENT_SUCCESS) {
      break;
    }
    printf("MQTT connection failed (attempt %d/10), retrying in 2 seconds...\n", retry_count + 1);
    sleep(2);
    retry_count++;
  }

  if (rc != MQTTCLIENT_SUCCESS) {
      printf("Failed to connect to broker\n");
      mqtt_connected = false;
      return;
  } else {
      printf("Connected to MQTT broker ...\n");
      mqtt_connected = true;
     // lv_label_set_text(guider_ui.pageStatic_label_1, "");
  }
    // Topics are defined in MQTT_TOPICS array at the top of the file
    subscribe_to_mqtt_topics();

  ////////////////////////replace subscription end
}

void set_max_temp(){
  pubmsg.payload = "12"; 
  pubmsg.payloadlen = (int)strlen("12"); 
  pubmsg.qos = QOS; 
  pubmsg.retained = 0;
  
  MQTTClient_publishMessage(client, "everest_external/nodered/1/cmd/set_max_current", &pubmsg, NULL); 
  printf("Message published: %s\n", "12");
}


void plug_in(){
  pubmsg.payload = "sleep 1;iec_wait_pwr_ready;sleep 1;draw_power_regulated 16,3;sleep 36000;unplug"; 
  pubmsg.payloadlen = (int)strlen("sleep 1;iec_wait_pwr_ready;sleep 1;draw_power_regulated 16,3;sleep 36000;unplug"); 
  pubmsg.qos = QOS; 
  pubmsg.retained = 0;
  
  MQTTClient_publishMessage(client, "everest_external/nodered/1/carsim/cmd/execute_charging_session", &pubmsg, NULL); 
  printf("Message published: %s\n", "sleep 1;iec_wait_pwr_ready;sleep 1;draw_power_regulated 16,3;sleep 36000;unplug");
}

void unplug(){
  pubmsg.payload = "unplug"; 
  pubmsg.payloadlen = (int)strlen("unplug"); 
  pubmsg.qos = QOS; 
  pubmsg.retained = 0;

  UPDATE_LABEL_SAFE(guider_ui.screen_label_27, label_energy_buffer, final_energy);
  UPDATE_LABEL_SAFE(guider_ui.screen_label_28, label_energy_buffer, final_energy);
  MQTTClient_publishMessage(client, "everest_external/nodered/1/carsim/cmd/modify_charging_session", &pubmsg, NULL); 
  printf("Message published: %s\n", "unplug"); 
}

// void pause_charging(){
//   pubmsg.payload = "pause_charging"; 
//   pubmsg.payloadlen = (int)strlen("pause_charging"); 
//   pubmsg.qos = QOS; 
//   pubmsg.retained = 0;
  
//   MQTTClient_publishMessage(client, "everest_external/nodered/1/cmd/pause_charging", &pubmsg, NULL); 
//   printf("Message published: %s\n", "pause_charging"); 
//   active_session = false;
// }
 void pause_charging(){
  printf("\n========================================\n");
  printf("=== PAUSE_CHARGING CALLED ===\n");
  printf("========================================\n");
  
  // Get current time BEFORE capture
  time_t rawtime;
  struct tm * timeinfo;
  time(&rawtime);
  timeinfo = localtime(&rawtime);
  printf("System time NOW: %02d:%02d:%02d\n", 
         timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
  
  printf("Before capture:\n");
  printf("  pause_time_captured = %d\n", pause_time_captured);
  if (pause_time_captured) {
      printf("  OLD pauseTime: %02d:%02d:%02d %s\n", 
             pauseTime.hours, pauseTime.minutes, pauseTime.seconds,
             (pauseTime.ampm == 'A') ? "AM" : "PM");
  }
  
  // Capture pause time immediately when pause is triggered
  set_screen_digital_clock_1();
  pauseTime.hours = atoi(hour);
  pauseTime.minutes = atoi(minutes);
  pauseTime.seconds = atoi(seconds);
  pauseTime.ampm = (strcmp(am_pm, "AM") == 0) ? 'A' : 'P';
  pause_time_captured = true;
  
  printf("\nAfter capture:\n");
  printf("  NEW pauseTime: %02d:%02d:%02d %s\n", 
         pauseTime.hours, pauseTime.minutes, pauseTime.seconds,
         (pauseTime.ampm == 'A') ? "AM" : "PM");
  printf("  pause_time_captured = %d\n", pause_time_captured);
  printf("========================================\n\n");
  
  pubmsg.payload = "pause_charging"; 
  pubmsg.payloadlen = (int)strlen("pause_charging"); 
  pubmsg.qos = QOS; 
  pubmsg.retained = 0;
  
  MQTTClient_publishMessage(client, "everest_external/nodered/1/cmd/pause_charging", &pubmsg, NULL); 
  printf("Message published: %s\n", "pause_charging"); 
  active_session = false;
}

void resume_charging(){
  pubmsg.payload = "sleep 1;iec_wait_pwr_ready;sleep 1;draw_power_regulated 16,3;sleep 36000;pause_charging"; 
  pubmsg.payloadlen = (int)strlen("sleep 1;iec_wait_pwr_ready;sleep 1;draw_power_regulated 16,3;sleep 36000;pause_charging"); 
  pubmsg.qos = QOS; 
  pubmsg.retained = 0;
  
  MQTTClient_publishMessage(client, "everest_external/nodered/1/cmd/resume_charging", &pubmsg, NULL); 
  printf("Message published: %s\n", "sleep 1;iec_wait_pwr_ready;sleep 1;draw_power_regulated 16,3;sleep 36000;pause_charging"); 
}

static void screen_slider_1_event_custom_handler (lv_event_t *e)
{
    lv_obj_t * slider = lv_event_get_target(e);
    char buf[8];
    char publish_buffer[8];
    lv_snprintf(label_slider1_buffer, sizeof(label_slider1_buffer), "MAX: %d%%", (int)lv_slider_get_value(slider));
    lv_snprintf(publish_buffer, sizeof(buf), "%d%", (int)lv_slider_get_value(slider));
    lv_label_set_text_static(guider_ui.screen_label_6, label_slider1_buffer);
    pubmsg.payload = publish_buffer; 
    pubmsg.payloadlen = (int)strlen(publish_buffer); 
    pubmsg.qos = QOS; 
    pubmsg.retained = 0;
    
    MQTTClient_publishMessage(client, "everest_external/nodered/1/cmd/set_max_current", &pubmsg, NULL); 
    printf("Message published: %s\n", publish_buffer);
}
void increase_battery_level(){
  char battery_level_to_str[50];
  char totalKWattHr_to_str[50];
  int battery_level_to_int;
  char power_str[20];
  int power_int;

  // Get current time
  time_t current_time = time(NULL);
  
  // Only update if enough time has passed
  if (difftime(current_time, last_update_time) < UPDATE_INTERVAL_SECONDS) {
    return; // Skip this update
  }
  
  // Update the last update time
  last_update_time = current_time;


  if (active_session && (battery_level < max_limit)){
    set_paused = 1;
    
    // Use MQTT data if available, otherwise simulate
    if (mqtt_battery_level >= 0.0f) {
        // Use MQTT battery level
        battery_level = mqtt_battery_level;
    } else {
        // Simulate battery increase (existing logic)
        battery_level += 0.1;
    }
    
    totalKWattHr += 0.0050;
    sprintf(battery_level_to_str, "%.1f", battery_level);
    
    // Use real MQTT energy data if available, otherwise use simulated
    if (mqtt_energy_kwh > 0) {
        sprintf(totalKWattHr_to_str, "%.3f kWh", mqtt_energy_kwh);
    } else {
        sprintf(totalKWattHr_to_str, "%.3f kWh", totalKWattHr);
    }
     
    
    UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "Charging");
    lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xd0ff00), LV_PART_MAIN|LV_STATE_DEFAULT);
    
    battery_level_to_int = (int)battery_level;
    UPDATE_LABEL_SAFE(guider_ui.screen_label_38, label_battery_buffer, battery_level_to_str);
    UPDATE_LABEL_SAFE(guider_ui.screen_label_19, label_battery_buffer, battery_level_to_str);
    
    UPDATE_LABEL_SAFE(guider_ui.screen_label_3, label_energy_buffer, totalKWattHr_to_str);
    UPDATE_LABEL_SAFE(guider_ui.screen_label_28, label_energy_buffer, totalKWattHr_to_str);
    
    lv_bar_set_value(guider_ui.screen_bar_2, battery_level_to_int, LV_ANIM_OFF);

      // Use real MQTT power data if available, otherwise use simulated
      if (mqtt_power_kw > 0) {
          power_int = (int)mqtt_power_kw;
          sprintf(power_str, "%.0f", mqtt_power_kw);
      } else {
          power_int = 8;
          sprintf(power_str, "8");
      }
 
      lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, power_int);
      UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, power_str);

    //add estimated end time
    float remaining_charge;
    remaining_charge = max_limit - battery_level;
    int remaining_time_in_seconds;
    remaining_time_in_seconds = remaining_charge * 10;
    char diff_time[20];
    diffTime = secondsToTime(remaining_time_in_seconds);
    snprintf(diff_time, sizeof(diff_time), "00:%02d:%02d", diffTime.minutes, diffTime.seconds);
    UPDATE_LABEL_SAFE(guider_ui.screen_label_11, label_duration_buffer, diff_time);
    //add estimated end time
  }else{

    if (set_paused == 1){
      printf("Automatic pause triggered (battery limit reached)\n");
      pause_charging();  // This will now capture pause time inside the function
      printf("\nready to pause: elseIf\n");
      lv_obj_clear_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
      UPDATE_LABEL_SAFE(guider_ui.screen_label_11, label_duration_buffer, "00:00:00");
      // Add dial data
        lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, 0);
        UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, "0");
      // Add dial data
      set_paused = 0; 
    }
  }

}

static void screen_slider_2_event_custom_handler (lv_event_t *e)
{
    lv_obj_t * slider = lv_event_get_target(e);
    char buf[8];
    char publish_buffer[8];
    // lv_snprintf(buf, sizeof(buf), "%d% %", (char)lv_slider_get_value(slider));
    lv_snprintf(label_slider2_buffer, sizeof(label_slider2_buffer), "%d%%", (int)lv_slider_get_value(slider));
    max_limit = lv_slider_get_value(slider);
    lv_label_set_text_static(guider_ui.screen_label_34, label_slider2_buffer);
}

static void screen_sw_1_event_custom_handler (lv_event_t *e)
{
  lv_event_code_t code = lv_event_get_code(e);

  
	switch (code) {
	case LV_EVENT_VALUE_CHANGED:
	{
		lv_obj_t * status_obj = lv_event_get_target(e);
		int status = lv_obj_has_state(status_obj, LV_STATE_CHECKED) ? 1 : 0;
		switch(status) {
		case 0:
		{
			// lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_arial_30, 0);
          
            // MQTTClient_message pubmsg = MQTTClient_message_initializer; 
            unplug(); 
            UPDATE_LABEL_SAFE(guider_ui.screen_label_10, label_time_buffer, "--:--:--");
            lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
            // lv_obj_add_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
            // lv_obj_add_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
            // lv_obj_add_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
            // lv_obj_add_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
    		lv_obj_add_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
    		lv_obj_add_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
    		lv_obj_add_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
			break;
		}
		case 1:
		{
			// lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_arial_30, 0);
          
            // MQTTClient_message pubmsg = MQTTClient_message_initializer; 
            //UPDATE_LABEL_SAFE(guider_ui.screen_label_10, label_time_buffer, "12:12:12");
            plug_in();
            is_new_session = true;			
			break;
		}
		default:
			break;
		}
		break;
	}
	default:
		break;
	}
}


static void screen_img_18_custom_event_custom_handler (lv_event_t *e)
{
  // pause_charging();
  UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "final_energy: Pause");
}

static void screen_img_19_custom_event_custom_handler (lv_event_t *e)
{
  // resume_charging();
  is_new_session = false;
  UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "final_energy: Play");
}

static void screen_sw_2_custom_event_custom_handler (lv_event_t *e)
{
  lv_event_code_t code = lv_event_get_code(e);
	switch (code) {
	case LV_EVENT_VALUE_CHANGED:
	{
		lv_obj_t * status_obj = lv_event_get_target(e);
		int status = lv_obj_has_state(status_obj, LV_STATE_CHECKED) ? 1 : 0;
		switch(status) {
		case 0:
		{
            pause_charging();
            printf("hello pause sw_2");
			break;
		}
		case 1:
		{
            resume_charging();
            printf("hello resume sw_2");
            is_new_session = false;
			break;
		}
		default:
			break;
		}
		break;
	}
	default:
		break;
	}
}
