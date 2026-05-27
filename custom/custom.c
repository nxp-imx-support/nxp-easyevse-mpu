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
#include <math.h>

// Add these includes at the top if not already present
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>


LV_IMG_DECLARE(_arrow_red_alpha_80x67);
LV_IMG_DECLARE(_arrow_green_alpha_80x67);

/*********************
 *      DEFINES
 *********************/
#define ADDRESS     "localhost:1883" // Example broker 
#define CLIENTID    "MQTTClient" 
#define QOS         1 
#define TIMEOUT     10000L 

// ============================================
// EVEREST DIRECT API TOPICS (No Node-RED dependency)
// ============================================
#define EVSE_MODULE_ID          "evse_manager_1"
#define EVSE_PAUSE_TOPIC        "everest_api/evse_manager_1/cmd/pause_charging"
#define EVSE_RESUME_TOPIC       "everest_api/evse_manager_1/cmd/resume_charging"

/**********************
 *  MQTT TOPICS ARRAY
 *********************/
// Centralized MQTT topics - used for initial subscription and reconnection
static const char* MQTT_TOPICS[] = {
    "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/session_event",
    "everest_api/ocpp/var/connection_status",
    "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/evse_id",
    "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/ev_info",
    "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/selected_protocol",
    "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/powermeter",
    "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/hw_capabilities",
    "everest_api/1/auth_consumer/auth_api/e2m/token_validation_status",
    "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/session_info" 
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

// Session info helper prototypes
static bool parse_iso8601_to_local(const char *iso_time, char *output, size_t output_size);
static void format_duration_seconds(int total_seconds, char *output, size_t output_size);


// Battery level calculation prototypes
// Returns SOC percentage (0-100) or -1 if invalid
static float calculate_battery_soc(float remaining_energy_wh);
// Updates label_38, label_19, and screen_bar_2 with SOC value
static void update_battery_display(float soc);


// Estimated time calculation prototype (Feature 2)
static void update_estimated_remaining_time(float remaining_energy_wh, float rate_wh_per_sec);

// ============================================
// PENDING STATE UPDATE (Thread-safe LVGL updates)
// ============================================
static bool pending_state_update = false;
static char pending_state_text[64] = "";
static uint32_t pending_state_color = 0xdcd1e5;


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
float battery_level = 00.0f;
bool active_session=false;
int max_limit=100;
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

// ============================================
// BATTERY LEVEL CALCULATION VARIABLES
// ============================================
// Battery capacity - configure based on your EV
// Example: 555 Wh derived from user's test data (444 Wh = 80% remaining)
static const float DEFAULT_BATTERY_CAPACITY_WH = 555.0f;
static float battery_capacity_wh = 555.0f;  // Can be updated dynamically if needed

// Current remaining energy from ev_info (updated on each MQTT message)
static float initial_remaining_energy_wh = -1.0f;   // Captured at session start from ev_info
static float current_remaining_energy_wh = -1.0f;   // Latest calculated value
static bool initial_remaining_captured = false;      // Flag: initial value captured

// Target SOC for charging (100% for now, can be made configurable later)
static const float TARGET_SOC = 100.0f;

// Flag to stop updates when battery reaches 100%
static bool charging_complete = false;


// ============================================
// PENDING SESSION END (Minimal - Image + Popup only)
// ============================================
static bool pending_show_popup = false;
static bool pending_change_image = false;
static const lv_img_dsc_t *pending_image_src = NULL;
static uint32_t pending_image_tick = 0;


// ============================================
// ESTIMATED TIME CALCULATION VARIABLE
// ============================================
// Charging rate tracking - calculated from session_info
static float charging_rate_wh_per_sec = 0.0f;

// EMA smoothing for stable ETA display
static float smoothed_charging_rate = 0.0f;
static const float EMA_ALPHA = 0.2f;  // Smoothing factor (0.2 = balanced)


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
static char label_energy_buffer[32] = "0.000 kWh";
static char label_energy_buffer_mqtt[32];
static char label_energy_buffer_mqtt_summary[32];
static char label_temp_buffer[16] = "0";
static char label_power_buffer[16] = "0";
static char label_battery_buffer[16] = "00.0";
static char label_time_buffer[32] = "--:--:--";
static char label_start_time_main[32];    // for label_10
static char label_start_time_summary[32]; // for label_29
static char label_evse_id_buffer[128] = "EVSE ID: NA";
static char label_ev_id_buffer[128] = "EV ID: NA";
static char label_iso_mode_buffer[32] = "ISO Mode: NA";
static char label_protocol_buffer[64] = "Protocol: NA";
static char label_voltage_buffer[32] = "Voltage: NA";
static char label_direction_buffer[32] = "Direction: NA";
static char label_meter_buffer[64] = "Meter: NA";
static char label_connector_buffer[64] = "Connector: NA";
static char label_uid_buffer[64] = "UID: NA";
static char label_card_type_buffer[64] = "Type: NA";
static char label_card_status_buffer[64] = "Status: NA";
static char label_auth_type_buffer[64] = "Auth: NA";
static char label_current_buffer[32] = "0.0 A";
static char label_duration_buffer[32] = "00:00:00";
static char label_duration_buffer_mqtt[32];
static char label_end_time_buffer[32] = "00:00:00 AM";
static char label_ip_buffer[32] = "(No IP)";
static char label_network_buffer[16] = "Unknown";
static char label_location_buffer[64] = "NXP Plot 1";
static char label_slider1_buffer[16] = "MAX: 0%";
static char label_slider2_buffer[16] = "0%";
static bool is_mqtt_end_time_captured=false;
static char label_event_buffer[64] = "";


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

// Add this timer callback
static void internet_check_timer_cb(lv_timer_t *timer) {
    int result = system("ping -c 1 8.8.8.8 -W 1 2>/dev/null 1>/dev/null");
    
    if (result == 0) {
        lv_obj_add_flag(guider_ui.screen_label_13, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(guider_ui.screen_img_6, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(guider_ui.screen_img_17, LV_OBJ_FLAG_HIDDEN);
    } else {
        lv_obj_clear_flag(guider_ui.screen_label_13, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(guider_ui.screen_img_6, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(guider_ui.screen_img_17, LV_OBJ_FLAG_HIDDEN);
    }
}

// Timer callback to apply pending state label update (runs in LVGL main thread)
static void state_update_timer_cb(lv_timer_t * timer)
{
    if (pending_state_update) {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, pending_state_text);
        lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(pending_state_color), LV_PART_MAIN|LV_STATE_DEFAULT);
        lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_arial_30, 0);
        lv_obj_invalidate(guider_ui.screen_label_1);
        
        printf(">>> STATE APPLIED TO UI: '%s' <<<\n", pending_state_text);
        
        pending_state_update = false;
    }

    // ========== Handle pending background image change ==========
    if (pending_change_image) {
        if (pending_image_src != NULL) {
            lv_img_set_src(guider_ui.screen_img_2, pending_image_src);
            printf(">>> Background image changed (thread-safe) <<<\n");
        }
        pending_change_image = false;
        pending_image_src = NULL;
        pending_image_tick = lv_tick_get();  // Record when image was set
    }

    // ========== Handle pending popup display (after image settles) ==========
    if (pending_show_popup) {
        uint32_t elapsed = lv_tick_get() - pending_image_tick;
        // Wait 150ms after image change before showing popup
        if (elapsed >= 150) {
            lv_obj_clear_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
            printf(">>> Popup displayed (thread-safe, after image) <<<\n");
            pending_show_popup = false;
        }
    }

}

void custom_init(lv_ui *ui)
{
    /* Add your codes here */
  get_mqtt_state_for_evse();
  set_screen_digital_clock_1();

  lv_timer_t * clock_timer = lv_timer_create(clock_update_timer_cb, 1000, NULL);
  lv_timer_t *internet_timer = lv_timer_create(internet_check_timer_cb, 30000, NULL);

  // Create state update timer (every 50ms for responsive UI)
  lv_timer_t * state_timer = lv_timer_create(state_update_timer_cb, 50, NULL);


  // Show cont_4 overlay by default (waiting for EVerest/MQTT)
  lv_obj_clear_flag(guider_ui.screen_cont_4, LV_OBJ_FLAG_HIDDEN);

  // Create watchdog timer to check MQTT activity every 1 second
  lv_timer_t * mqtt_watchdog = lv_timer_create(mqtt_watchdog_timer_cb, 1000, NULL);

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
  // Initialize Meter ID label (was Sigboard - now shows powermeter meter_id)
  UPDATE_LABEL_SAFE(guider_ui.screen_label_56, label_meter_buffer, "Meter: NA");

  // Initialize Connector Type label (shows connector_type from hw_capabilities)
  UPDATE_LABEL_SAFE(guider_ui.screen_label_connector, label_connector_buffer, "Connector: NA");

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

  // Initialize Authorization Type label
  UPDATE_LABEL_SAFE(guider_ui.screen_label_62, label_auth_type_buffer, "Auth: NA");

  // Initialize Current L1 display
  UPDATE_LABEL_SAFE(guider_ui.screen_label_60, label_current_buffer, "0.0 A");
//   printf("Current L1 initialized to: 0.0 A\n");

  UPDATE_LABEL_SAFE(guider_ui.screen_label_63, label_event_buffer, "Enabled");

  lv_obj_add_event_cb(ui->screen_sw_1, screen_sw_1_event_custom_handler, LV_EVENT_ALL, ui);
  lv_obj_add_event_cb(ui->screen_sw_2, screen_sw_2_custom_event_custom_handler, LV_EVENT_ALL, ui);
  //lv_obj_add_event_cb(ui->screen_img_18, screen_img_18_custom_event_custom_handler, LV_EVENT_ALL, ui);
  lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
  lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_DISABLED);

  //   lv_obj_add_event_cb(ui->screen_slider_1, screen_slider_1_event_custom_handler, LV_EVENT_VALUE_CHANGED, NULL);
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

/**********************
 *  SESSION INFO HELPERS
 **********************/

// Helper: Parse ISO 8601 timestamp to local time string
// Input:  "2026-03-31T11:24:23.171Z"
// Output: "11:24:23 AM" (local time)
static bool parse_iso8601_to_local(const char *iso_time, char *output, size_t output_size) {
    if (iso_time == NULL || output == NULL) {
        return false;
    }
    
    int year, month, day, hour, min, sec;
    
    // Parse ISO 8601 format: YYYY-MM-DDTHH:MM:SS.sssZ
    int parsed = sscanf(iso_time, "%d-%d-%dT%d:%d:%d", 
                        &year, &month, &day, &hour, &min, &sec);
    
    if (parsed != 6) {
        printf("Failed to parse ISO 8601 timestamp: %s\n", iso_time);
        return false;
    }
    
    // Build UTC time structure
    struct tm tm_utc = {0};
    tm_utc.tm_year = year - 1900;
    tm_utc.tm_mon = month - 1;
    tm_utc.tm_mday = day;
    tm_utc.tm_hour = hour;
    tm_utc.tm_min = min;
    tm_utc.tm_sec = sec;
    tm_utc.tm_isdst = -1;
    
    // Convert UTC to epoch time
    time_t utc_time = timegm(&tm_utc);
    if (utc_time == -1) {
        printf("Failed to convert UTC time for: %s\n", iso_time);
        return false;
    }
    
    // Convert epoch to local time
    struct tm *local_time = localtime(&utc_time);
    if (local_time == NULL) {
        printf("Failed to convert to local time\n");
        return false;
    }
    
    // Format as 12-hour with AM/PM
    int hour_12 = local_time->tm_hour % 12;
    if (hour_12 == 0) hour_12 = 12;
    const char *ampm = (local_time->tm_hour >= 12) ? "PM" : "AM";
    
    snprintf(output, output_size, "%02d:%02d:%02d %s", 
             hour_12, local_time->tm_min, local_time->tm_sec, ampm);
    return true;
}

// Helper: Convert seconds to HH:MM:SS format
// Input:  13 seconds
// Output: "00:00:13"
// Input:  3665 seconds
// Output: "01:01:05"
static void format_duration_seconds(int total_seconds, char *output, size_t output_size) {
    if (output == NULL) {
        return;
    }
    
    // Handle negative values
    if (total_seconds < 0) {
        total_seconds = 0;
    }
    
    int hours = total_seconds / 3600;
    int minutes = (total_seconds % 3600) / 60;
    int seconds = total_seconds % 60;
    
    snprintf(output, output_size, "%02d:%02d:%02d", hours, minutes, seconds);
}

// ============================================
// BATTERY SOC CALCULATION HELPER
// ============================================
/**
 * Calculate current State of Charge (SOC) from remaining energy
 * 
 * Formula: SOC = 100 - (remaining_energy / capacity × 100)
 * 
 * @param remaining_energy_wh  Current remaining energy needed to reach 100% (Wh)
 * @return Current SOC percentage (0-100), or -1 if cannot calculate
 * 
 * Examples with 555 Wh capacity:
 *   remaining = 444 Wh → SOC = 100 - (444/555×100) = 20%
 *   remaining = 312 Wh → SOC = 100 - (312/555×100) = 43.8%
 *   remaining = 0 Wh   → SOC = 100%
 */
static float calculate_battery_soc(float remaining_energy_wh) {
    // If remaining energy is 0 or negative, battery is full
    if (remaining_energy_wh <= 0) {
        return 100.0f;
    }
    
    // If capacity is invalid, cannot compute SOC
    if (battery_capacity_wh <= 0) {
        printf("ERROR: Invalid battery capacity (%.2f Wh)\n", battery_capacity_wh);
        return -1.0f;
    }
    
    // SOC = 100 - (remaining / capacity × 100)
    float soc = 100.0f - (remaining_energy_wh / battery_capacity_wh * 100.0f);
    
    // Clamp to valid range [0, 100]
    if (soc < 0.0f) {
        soc = 0.0f;
    }
    if (soc > 100.0f) {
        soc = 100.0f;
    }
    
    return soc;
}

/**
 * Update battery level display on UI components
 * Updates: label_38, label_19 (percentage text), screen_bar_2 (progress bar)
 * 
 * @param soc  State of Charge percentage (0-100)
 */
static void update_battery_display(float soc) {
    // Skip if invalid SOC
    if (soc < 0) {
        return;
    }
    
    // Format SOC as string with 1 decimal place
    char soc_str[16];
    snprintf(soc_str, sizeof(soc_str), "%.1f", soc);
    
    // Update battery level labels
    UPDATE_LABEL_SAFE(guider_ui.screen_label_38, label_battery_buffer, soc_str);
    UPDATE_LABEL_SAFE(guider_ui.screen_label_19, label_battery_buffer, soc_str);
    
    // Update battery progress bar (integer value)
    int soc_int = (int)soc;
    lv_bar_set_value(guider_ui.screen_bar_2, soc_int, LV_ANIM_OFF);
    
    // Update global battery_level variable for other functions
    battery_level = soc;
}

// ============================================
// ESTIMATED REMAINING TIME HELPER (Feature 2)
// ============================================
/**
 * Calculate and update estimated remaining charging time
 * 
 * Formula: remaining_time = remaining_energy / charging_rate
 * 
 * @param remaining_energy_wh  Energy still needed to reach 100% (Wh)
 * @param rate_wh_per_sec      Current charging rate (Wh per second)
 * 
 * Updates: label_11 (estimated time remaining display)
 * 
 * Examples:
 *   remaining=400 Wh, rate=0.5 Wh/s → 800 sec → 00:13:20
 *   remaining=200 Wh, rate=1.0 Wh/s → 200 sec → 00:03:20
 *   remaining=0 Wh                  → 00:00:00 (fully charged)
 */
// ============================================
// ESTIMATED REMAINING TIME HELPER (Feature 2)
// ============================================
/**
 * Calculate and update estimated remaining charging time
 * Uses Exponential Moving Average (EMA) to smooth rate fluctuations
 * 
 * Formula: smoothed_rate = alpha × current + (1-alpha) × previous
 * 
 * @param remaining_energy_wh  Energy still needed to reach 100% (Wh)
 * @param current_rate         Current instantaneous charging rate (Wh/s)
 * 
 * Updates: label_11 (estimated time remaining display)
 */
// ============================================
// ESTIMATED REMAINING TIME HELPER (Feature 2)
// ============================================
/**
 * Calculate and update estimated remaining charging time
 * Uses Exponential Moving Average (EMA) to smooth rate fluctuations
 * Rate limited to update display only once per second
 * 
 * @param remaining_energy_wh  Energy still needed to reach 100% (Wh)
 * @param current_rate         Current instantaneous charging rate (Wh/s)
 * 
 * Updates: label_11 (estimated time remaining display)
 */
static void update_estimated_remaining_time(float remaining_energy_wh, float current_rate) {
    static time_t last_eta_update_time = 0;
    char time_str[20];
    
    // Case 1: Fully charged
    if (remaining_energy_wh <= 0) {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_11, label_duration_buffer, "00:00:00");
        smoothed_charging_rate = 0.0f;
        return;
    }
    
    // Case 2: Invalid rate (not charging or paused)
    if (current_rate <= 0.001f) {
        UPDATE_LABEL_SAFE(guider_ui.screen_label_11, label_duration_buffer, "--:--:--");
        return;
    }
    
    // Apply Exponential Moving Average (EMA) for smoothing
    // This runs every call to keep the rate accurate
    if (smoothed_charging_rate <= 0.001f) {
        smoothed_charging_rate = current_rate;
    } else {
        smoothed_charging_rate = (EMA_ALPHA * current_rate) + 
                                 ((1.0f - EMA_ALPHA) * smoothed_charging_rate);
    }
    
    // ========== Rate limit display updates to once per second ==========
    time_t now = time(NULL);
    if (last_eta_update_time > 0 && difftime(now, last_eta_update_time) < 1.0) {
        return;  // Skip display update, not yet 1 second
    }
    last_eta_update_time = now;
    // ====================================================================
    
    // Calculate remaining time using smoothed rate
    float remaining_seconds_f = remaining_energy_wh / smoothed_charging_rate;
    
    // Cap at 99:59:59 to prevent display overflow
    if (remaining_seconds_f > 359999.0f) {
        remaining_seconds_f = 359999.0f;
    }
    
    int remaining_seconds = (int)remaining_seconds_f;
    
    // Convert to hours, minutes, seconds
    int hours = remaining_seconds / 3600;
    int minutes = (remaining_seconds % 3600) / 60;
    int seconds = remaining_seconds % 60;
    
    // Format as HH:MM:SS
    snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d", hours, minutes, seconds);
    UPDATE_LABEL_SAFE(guider_ui.screen_label_11, label_duration_buffer, time_str);
}

// Thread-safe function to request state label update (called from MQTT thread)
static void request_state_update(const char *state_text, uint32_t color) {
    strncpy(pending_state_text, state_text, sizeof(pending_state_text) - 1);
    pending_state_text[sizeof(pending_state_text) - 1] = '\0';
    pending_state_color = color;
    pending_state_update = true;
    
    printf(">>> STATE UPDATE QUEUED: '%s' <<<\n", state_text);
}

int messageArrived(void *context, char *topic, int topicLen, MQTTClient_message *message) {

    static unsigned long msg_count = 0;
    static time_t last_rate_check = 0;
    static unsigned long last_msg_count = 0;
    static time_t last_mem_check = 0; 
    
    msg_count++;
    time_t now = time(NULL);

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
    
    if (strcmp(topic,"everest_api/1/evse_manager_consumer/evse_manager_api/e2m/session_event") == 0){

            char *payload_str = (char *)message->payload;
            char event_value[64] = {0};
            
            // Parse "event" field from JSON: {"event": "SessionFinished", ...}
            char *event_field = strstr(payload_str, "\"event\"");
            
            if (event_field != NULL) {
                // Skip past "event"
                event_field += 7;
                
                // Skip whitespace, colon, whitespace, and opening quote
                while (*event_field == ' ' || *event_field == '\t' || *event_field == ':' || *event_field == '"') {
                    event_field++;
                }
                
                // Find closing quote
                char *end_quote = strchr(event_field, '"');
                
                if (end_quote != NULL && (end_quote - event_field) > 0) {
                    int len = (end_quote - event_field) < 63 ? (end_quote - event_field) : 63;
                    strncpy(event_value, event_field, len);
                    event_value[len] = '\0';
                }
            }
            
            // Log parsed event
            printf("=== SESSION EVENT: '%s' ===\n", event_value);
        //#########################################################################################
            if (strlen(event_value) > 0) {
                UPDATE_LABEL_SAFE(guider_ui.screen_label_63, label_event_buffer, event_value);
            }


            // ============================================
            // CENTRALIZED STATE MAPPING
            // ============================================
            printf(">>> ENTERING STATE MAPPING for event: '%s' <<<\n", event_value);
            
            const char *display_state = NULL;
            uint32_t state_color = 0xdcd1e5;  // Default gray
            bool state_handled = false;
            
            // ============================================
            // SINGLE LABEL UPDATE POINT (Thread-safe)
            // ============================================
            if (display_state != NULL) {
                printf(">>> REQUESTING STATE UPDATE: '%s' -> '%s' (color: 0x%06X) <<<\n", 
                    label_state_buffer, display_state, state_color);
                
                // Thread-safe: Queue update for LVGL main thread
                request_state_update(display_state, state_color);
            }



      if (
          strcmp(event_value, "TransactionFinished") == 0 ||
          strcmp(event_value, "SessionFinished") == 0 ||
          strcmp(event_value, "Enabled") == 0 ||
          strcmp(event_value, "ChargingFinished") == 0
      ) {
          
          // Skip if already processed to prevent duplicate processing
          if (session_end_processed) {

              UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "Unplugged");
              UPDATE_LABEL_SAFE(guider_ui.screen_label_57, label_uid_buffer, "UID: NA");
              UPDATE_LABEL_SAFE(guider_ui.screen_label_58, label_card_type_buffer, "Type: NA");
              UPDATE_LABEL_SAFE(guider_ui.screen_label_62, label_auth_type_buffer, "Auth: NA");
              UPDATE_LABEL_SAFE(guider_ui.screen_label_59, label_card_status_buffer, "Status: NA");
              UPDATE_LABEL_SAFE(guider_ui.screen_label_55, label_direction_buffer, "Direction: NA");
              UPDATE_LABEL_SAFE(guider_ui.screen_label_44, label_ev_id_buffer, "EV ID: NA");
              lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
              UPDATE_LABEL_SAFE(guider_ui.screen_label_53, label_protocol_buffer, "Protocol: NA");
              MQTTClient_freeMessage(&message);
              MQTTClient_free(topic);
              return 1;
          }
          
          // Mark as processed immediately
          session_end_processed = true;

          // ========== Reset battery calculation variable ==========
          initial_remaining_energy_wh = -1.0f;
          current_remaining_energy_wh = -1.0f;
          initial_remaining_captured = false;
          charging_rate_wh_per_sec = 0.0f;
          smoothed_charging_rate = 0.0f;
          charging_complete = false;  // Reset for new session
          printf("Battery and ETA calculation variables reset for new session\n");
          // =========================================================
          
          // Get current system time
          time_t rawtime;
          struct tm * timeinfo;
          time(&rawtime);
          timeinfo = localtime(&rawtime);
          
          active_session = false;
          start_time_captured = false;  // Keep this here
          // pause_time_captured will be reset later
          
          lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xdcd1e5), LV_PART_MAIN|LV_STATE_DEFAULT);
        //   lv_img_set_src(guider_ui.screen_img_2, &_Car_Unplugged_0_alpha_1277x797);
        //   replaced with below
        // Queue image change for main thread (prevents glitch)
        pending_image_src = &_Car_Unplugged_0_alpha_1277x797;
        pending_change_image = true;

          
          // migrated_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_
          UPDATE_LABEL_SAFE(guider_ui.screen_label_10, label_time_buffer, "--:--:--");
          UPDATE_LABEL_SAFE(guider_ui.screen_label_1, label_state_buffer, "Unplugged");
          lv_obj_add_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_img_19, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
          // Reset NFC Card UID and Type (always, regardless of session state)
          UPDATE_LABEL_SAFE(guider_ui.screen_label_57, label_uid_buffer, "UID: NA");
          UPDATE_LABEL_SAFE(guider_ui.screen_label_58, label_card_type_buffer, "Type: NA");
          UPDATE_LABEL_SAFE(guider_ui.screen_label_62, label_auth_type_buffer, "Auth: NA");
          UPDATE_LABEL_SAFE(guider_ui.screen_label_59, label_card_status_buffer, "Status: NA");
          UPDATE_LABEL_SAFE(guider_ui.screen_label_55, label_direction_buffer, "Direction: NA");
          UPDATE_LABEL_SAFE(guider_ui.screen_label_44, label_ev_id_buffer, "EV ID: NA");
          lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
          UPDATE_LABEL_SAFE(guider_ui.screen_label_53, label_protocol_buffer, "Protocol: NA");
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
            printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            // lv_obj_clear_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
            // replaced with below
            // Queue popup display for main thread (after image settles)
            if (strcmp(event_value, "Enabled") != 0) {
                pending_show_popup = true;
            }

            printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
            battery_level = 00.0;
            totalKWattHr = 0.000;
            mqtt_power_kw = 0.0f;
            mqtt_energy_kwh = 0.0f;
            UPDATE_LABEL_SAFE(guider_ui.screen_label_38, label_battery_buffer, "00.0");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_19, label_battery_buffer, "00.0");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_3, label_energy_buffer, "0.000 kWh");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_11, label_duration_buffer, "--:--:--");
            lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, 0);
            UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, "0");
            lv_bar_set_value(guider_ui.screen_bar_2, 20, LV_ANIM_OFF);
            UPDATE_LABEL_SAFE(guider_ui.screen_label_57, label_uid_buffer, "UID: NA");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_58, label_card_type_buffer, "Type: NA");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_62, label_auth_type_buffer, "Auth: NA");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_59, label_card_status_buffer, "Status: NA");
            lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
            UPDATE_LABEL_SAFE(guider_ui.screen_label_55, label_direction_buffer, "Direction: NA");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_44, label_ev_id_buffer, "EV ID: NA");
            UPDATE_LABEL_SAFE(guider_ui.screen_label_53, label_protocol_buffer, "Protocol: NA");

            is_session_started = false;
            printf("Session values reset (is_session_started was true)\n");
          }

          pause_time_captured = false;
        // migrated_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_
      }
      // Capture pause time (handles both manual and automatic pause)
      // Capture pause time (handles both manual and automatic pause)
      if (strcmp(event_value, "EVSE Paused") == 0 ||
          strcmp(event_value, "ChargingPausedEV") == 0 ||
          strcmp(event_value, "ChargingPausedEVSE") == 0) {
          set_screen_digital_clock_1();
          pauseTime.hours = atoi(hour);
          pauseTime.minutes = atoi(minutes);
          pauseTime.seconds = atoi(seconds);
          pauseTime.ampm = (strcmp(am_pm, "AM") == 0) ? 'A' : 'P';
          pause_time_captured = true;
          // REMOVED: Label update - now handled in centralized state mapping above
      }


      // Existing grouped condition (keep as is)
      if (
          strcmp(event_value, "SessionStarted") == 0 ||
          strcmp(event_value, "AuthRequired") == 0 
      ) {
          active_session = false;
          lv_img_set_src(guider_ui.screen_img_2, &_Car_Unplugged_alpha_1280x800);

        //   lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xdcd1e5), LV_PART_MAIN|LV_STATE_DEFAULT);
      }

      if (
          strcmp(event_value, "AuthRequired") == 0
      ) {
          active_session = false;
          is_new_session = true;	
          lv_obj_add_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
      }
      
      if (strcmp(event_value, "ChargingStarted") == 0) {
          active_session = true;
          lv_img_set_src(guider_ui.screen_img_2, &_Car_plugged_alpha_1280x800);
          // REMOVED: Duplicate label update - now handled in centralized state mapping above
          
          lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
          
          if (!start_time_captured && is_session_started) {
              char string_time[20];
              set_screen_digital_clock_1();
              
              startTime.hours = atoi(hour);
              startTime.minutes = atoi(minutes);
              startTime.seconds = atoi(seconds); 
              startTime.ampm = (strcmp(am_pm, "AM") == 0) ? 'A' : 'P';
              
              snprintf(string_time, sizeof(string_time), "%s:%s:%s %s", hour, minutes, seconds, am_pm);
              
              UPDATE_LABEL_SAFE(guider_ui.screen_label_10, label_time_buffer, string_time);
              start_time_captured = true;
          }
      }

      if ((strcmp(event_value,"Authorized") == 0) && (is_new_session)){
        char string_time[20];
        set_screen_digital_clock_1();
        is_session_started = true;
        active_session = false;
        session_end_processed = false;  // ADD THIS LINE - Reset for new session

        // commenting for now - will be used later SOC related
        // lv_obj_clear_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
        // lv_obj_clear_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
        // lv_obj_clear_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
        // lv_obj_clear_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
        // commenting for now - will be used later
      }
      
    } else if (strcmp(topic,"everest_api/ocpp/var/connection_status") == 0){
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
    
    } else if (strcmp(topic, "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/ev_info") == 0) {
        // Validate payload
        if (message->payloadlen <= 0 || message->payload == NULL) {
            UPDATE_LABEL_SAFE(guider_ui.screen_label_44, label_ev_id_buffer, "EV ID: NA");
            printf("ev_info: Empty payload\n");
            MQTTClient_freeMessage(&message);
            MQTTClient_free(topic);
            return 1;
        }
        
        char *payload_str = (char *)message->payload;
        
        // Parse evcc_id field from JSON
        char *evcc_id_field = strstr(payload_str, "\"evcc_id\":");

        if (evcc_id_field != NULL) {
            evcc_id_field += 10;  // Skip past "evcc_id":
            
            // Skip whitespace and opening quote
            while (*evcc_id_field == ' ' || *evcc_id_field == '\t' || *evcc_id_field == '"') {
                evcc_id_field++;
            }
            
            // Find closing quote
            char *end_quote = strchr(evcc_id_field, '"');
            
            if (end_quote != NULL && (end_quote - evcc_id_field) > 0) {
                int evcc_id_len = end_quote - evcc_id_field;
                char evcc_id[96];
                int len = evcc_id_len < 95 ? evcc_id_len : 95;
                strncpy(evcc_id, evcc_id_field, len);
                evcc_id[len] = '\0';
                
                // Display as "EV ID: 00:01:01:65:76:30"
                char ev_id_display[128];
                snprintf(ev_id_display, sizeof(ev_id_display), "EV ID: %s", evcc_id);
                UPDATE_LABEL_SAFE(guider_ui.screen_label_44, label_ev_id_buffer, ev_id_display);
                printf("EV ID (EVCC): %s\n", evcc_id);
            } else {
                UPDATE_LABEL_SAFE(guider_ui.screen_label_44, label_ev_id_buffer, "EV ID: NA");
                printf("ev_info: Failed to parse evcc_id value\n");
            }
        } else {
            UPDATE_LABEL_SAFE(guider_ui.screen_label_44, label_ev_id_buffer, "EV ID: NA");
            printf("ev_info: evcc_id field not found in payload\n");
        }

        // ========== Parse remaining_energy_needed for battery SOC ==========
        // This value comes ONCE at session start - capture it as initial reference
        char *remaining_field = strstr(payload_str, "\"remaining_energy_needed\":");
        
        if (remaining_field != NULL) {
            remaining_field += 26;  // Skip past "remaining_energy_needed":
            
            // Skip whitespace
            while (*remaining_field == ' ' || *remaining_field == '\t') {
                remaining_field++;
            }
            
            // Parse the float value
            float remaining_energy = atof(remaining_field);
            
            // Only capture if we haven't captured yet AND value is valid
            if (!initial_remaining_captured && remaining_energy > 0) {
                initial_remaining_energy_wh = remaining_energy;
                current_remaining_energy_wh = remaining_energy;
                initial_remaining_captured = true;
                
                // Calculate initial SOC
                float initial_soc = calculate_battery_soc(remaining_energy);
                
                printf("=== Initial Battery State Captured ===\n");
                printf("Initial remaining energy: %.2f Wh\n", initial_remaining_energy_wh);
                printf("Battery capacity: %.2f Wh\n", battery_capacity_wh);
                printf("Initial SOC: %.1f%%\n", initial_soc);
                printf("=======================================\n");
                
                // Display initial SOC
                if (initial_soc >= 0) {
                    update_battery_display(initial_soc);
                }
            }
        } else {
            printf("ev_info: remaining_energy_needed field not found\n");
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
    } else if (strcmp(topic, "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/powermeter") == 0) {
    // Validate payload
        if (message->payloadlen <= 0 || message->payload == NULL) {
            MQTTClient_freeMessage(&message);
            MQTTClient_free(topic);
            return 1;
        }
        
        char *payload_str = (char *)message->payload;
        
        // Parse meter_id (top-level string in EVerest Powermeter type) -> screen_label_56 "Meter: <id>"
        char *meter_id_start = strstr(payload_str, "\"meter_id\":");
        if (meter_id_start == NULL) {
            meter_id_start = strstr(payload_str, "\"meter_id\" :");
        }
        if (meter_id_start != NULL) {
            char *value_start = strchr(meter_id_start, ':');
            if (value_start != NULL) {
                value_start++;
                while (*value_start == ' ' || *value_start == '\t' || *value_start == '\n' || *value_start == '\r') {
                    value_start++;
                }
                if (*value_start == '"') {
                    value_start++;
                    char *value_end = strchr(value_start, '"');
                    if (value_end != NULL && (value_end - value_start) > 0) {
                        int meter_id_len = value_end - value_start;
                        if (meter_id_len >= 48) meter_id_len = 47;
                        char meter_id_str[64];
                        strncpy(meter_id_str, value_start, meter_id_len);
                        meter_id_str[meter_id_len] = '\0';
                        snprintf(label_meter_buffer, sizeof(label_meter_buffer), "Meter: %s", meter_id_str);
                        lv_label_set_text_static(guider_ui.screen_label_56, label_meter_buffer);
                    }
                }
            }
        }

        // Parse voltage_V -> L1
        char *voltage_v_start = strstr(payload_str, "\"voltage_V\":");
        if (voltage_v_start != NULL) {
            char *l1_start = strstr(voltage_v_start, "\"L1\":");
            if (l1_start != NULL) {
                l1_start += 5;
                while (*l1_start == ' ' || *l1_start == '\t') {
                    l1_start++;
                }
                
                float voltage_l1 = atof(l1_start);
                static char voltage_display[32];
                snprintf(voltage_display, sizeof(voltage_display), "Voltage: %.1f V", voltage_l1);
                lv_label_set_text_static(guider_ui.screen_label_54, voltage_display);
                // printf("Voltage L1 (MQTT): %.1f V\n", voltage_l1);
            }
        }
        
        // Parse current_A -> L1
        char *current_a_start = strstr(payload_str, "\"current_A\":");
        if (current_a_start != NULL) {
            char *l1_start = strstr(current_a_start, "\"L1\":");
            if (l1_start != NULL) {
                l1_start += 5;
                while (*l1_start == ' ' || *l1_start == '\t') {
                    l1_start++;
                }
                
                float current_l1 = atof(l1_start);
                current_l1 = fabsf(current_l1);  // Always display as positive (V2G sends negative)
                snprintf(label_current_buffer, sizeof(label_current_buffer), "%.1f A", current_l1);
                lv_label_set_text_static(guider_ui.screen_label_60, label_current_buffer);
                // printf("Current L1 (MQTT): %.1f A\n", current_l1);

                // printf("Current L1 (MQTT): %.1f A\n", current_l1);
            }
        }

        // Parse temperatures array -> Body location
        char *temp_array_start = strstr(payload_str, "\"temperatures\":");
        if (temp_array_start != NULL) {
            // Find "Body" location within temperatures array
            char *body_location = strstr(temp_array_start, "\"location\": \"Body\"");
            
            if (body_location != NULL) {
                // Find temperature field after Body location
                char *temp_field = strstr(body_location, "\"temperature\":");
                
                if (temp_field != NULL) {
                    temp_field += 14;  // Skip past "temperature":
                    
                    while (*temp_field == ' ' || *temp_field == '\t' || *temp_field == ':') {
                        temp_field++;
                    }
                    
                    float temperature = atof(temp_field);
                    
                    static char temp_display[16];
                    snprintf(temp_display, sizeof(temp_display), "%.0f", temperature);
                    
                    lv_label_set_text_static(guider_ui.screen_label_4, temp_display);
                    // printf("Temperature (Body): %.1f°C\n", temperature);
                }
            }
        }

        increase_battery_level();      

    } else if (strcmp(topic, "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/hw_capabilities") == 0) {
         printf("\n========================================\n");
        printf(">>> HW_CAPABILITIES RECEIVED <<<\n");
        printf("Payload length: %d\n", message->payloadlen);
        printf("========================================\n");
        
        // Validate payload
        if (message->payloadlen <= 0 || message->payload == NULL) {
            UPDATE_LABEL_SAFE(guider_ui.screen_label_connector, label_connector_buffer, "Connector: NA");
            printf("ERROR: Empty payload\n");
            MQTTClient_freeMessage(&message);
            MQTTClient_free(topic);
            return 1;
        }
        
        // Print raw payload for debugging (truncate if too long)
        int print_len = message->payloadlen < 500 ? message->payloadlen : 500;
        printf("Raw payload: %.*s\n", print_len, (char *)message->payload);
        
        char *payload_str = (char *)message->payload;
        char *connector_start = strstr(payload_str, "\"connector_type\":");
        
        // Check if connector_type field exists
        if (connector_start == NULL) {
            // Try alternate formats
            connector_start = strstr(payload_str, "\"connector_type\" :");
            if (connector_start == NULL) {
                UPDATE_LABEL_SAFE(guider_ui.screen_label_connector, label_connector_buffer, "Connector: NA");
                printf("ERROR: connector_type field not found in payload\n");
                MQTTClient_freeMessage(&message);
                MQTTClient_free(topic);
                return 1;
            }
        }
        
        printf("Found connector_type at position: %ld\n", (long)(connector_start - payload_str));

        // Skip past "connector_type" and find the value
        char *value_start = strchr(connector_start, ':');
        if (value_start == NULL) {
            UPDATE_LABEL_SAFE(guider_ui.screen_label_connector, label_connector_buffer, "Connector: NA");
            printf("ERROR: No colon after connector_type\n");
            MQTTClient_freeMessage(&message);
            MQTTClient_free(topic);
            return 1;
        }
        
        value_start++;  // Skip past ':'
        
        // Skip whitespace and opening quote
        while (*value_start == ' ' || *value_start == '\t' || *value_start == '\n' || *value_start == '\r') {
            value_start++;
        }
        
        if (*value_start != '"') {
            UPDATE_LABEL_SAFE(guider_ui.screen_label_connector, label_connector_buffer, "Connector: NA");
            printf("ERROR: Expected quote after colon, got: '%c' (0x%02X)\n", *value_start, (unsigned char)*value_start);
            MQTTClient_freeMessage(&message);
            MQTTClient_free(topic);
            return 1;
        }
        
        value_start++;  // Skip opening quote
        
        // Find closing quote
        char *value_end = strchr(value_start, '"');
        if (value_end == NULL || (value_end - value_start) <= 0) {
            UPDATE_LABEL_SAFE(guider_ui.screen_label_connector, label_connector_buffer, "Connector: NA");
            printf("ERROR: No closing quote found\n");
            MQTTClient_freeMessage(&message);
            MQTTClient_free(topic);
            return 1;
        }

        // Extract connector type string
        int connector_len = value_end - value_start;
        if (connector_len >= 64) connector_len = 63;
        
        char connector_type[64];
        strncpy(connector_type, value_start, connector_len);
        connector_type[connector_len] = '\0';
        
        printf("Extracted connector_type: '%s' (length: %d)\n", connector_type, connector_len);
        
        // Map connector type to display string
        if (strcasestr(connector_type, "IEC62196Type2Cable") != NULL || 
            strcasestr(connector_type, "Type2Cable") != NULL) {
            snprintf(label_connector_buffer, sizeof(label_connector_buffer), "Connector: Type2 Cable");
            printf("Matched: Type2 Cable\n");
            
        } else if (strcasestr(connector_type, "IEC62196Type2Socket") != NULL || 
                   strcasestr(connector_type, "Type2Socket") != NULL) {
            snprintf(label_connector_buffer, sizeof(label_connector_buffer), "Connector: Type2 Socket");
            printf("Matched: Type2 Socket\n");
            
        } else if (strcasestr(connector_type, "Type1") != NULL) {
            snprintf(label_connector_buffer, sizeof(label_connector_buffer), "Connector: Type1");
            printf("Matched: Type1\n");
            
        } else if (strcasestr(connector_type, "CCS") != NULL) {
            snprintf(label_connector_buffer, sizeof(label_connector_buffer), "Connector: CCS");
            printf("Matched: CCS\n");
            
        } else if (strcasestr(connector_type, "CHAdeMO") != NULL) {
            snprintf(label_connector_buffer, sizeof(label_connector_buffer), "Connector: CHAdeMO");
            printf("Matched: CHAdeMO\n");
            
        } else if (strlen(connector_type) > 0) {
            // Unknown but valid connector - display raw value
            snprintf(label_connector_buffer, sizeof(label_connector_buffer), "Connector: %s", connector_type);
            printf("Unknown connector, using raw value: %s\n", connector_type);
            
        } else {
            snprintf(label_connector_buffer, sizeof(label_connector_buffer), "Connector: NA");
            printf("Empty connector type\n");
        }
        
        // Update the label (FIXED - always use the buffer directly)
        lv_label_set_text_static(guider_ui.screen_label_connector, label_connector_buffer);
        lv_obj_invalidate(guider_ui.screen_label_connector);  // Force redraw
        
        printf(">>> Connector label updated to: '%s' <<<\n", label_connector_buffer);
        printf("========================================\n\n");
    
    } else if (strcmp(topic, "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/session_info") == 0 ) {
        if (message->payloadlen <= 0 || message->payload == NULL) {
            printf("session_info: Empty payload\n");
            MQTTClient_freeMessage(&message);
            MQTTClient_free(topic);
            return 1;
        }

        char *payload_str = (char *)message->payload;

        // Parse transaction_start_time
        char *start_field = strstr(payload_str, "\"transaction_start_time\":");
        if (start_field != NULL) {
            start_field += 25;  // Skip past "transaction_start_time":
            
            // Skip whitespace and quotes
            while (*start_field == ' ' || *start_field == '\t' || *start_field == '"') {
                start_field++;
            }
            
            char *end_quote = strchr(start_field, '"');
            if (end_quote != NULL && (end_quote - start_field) > 0) {
                char iso_start[64];
                int len = (end_quote - start_field) < 63 ? (end_quote - start_field) : 63;
                strncpy(iso_start, start_field, len);
                iso_start[len] = '\0';
                
                char local_time[32];
                if (parse_iso8601_to_local(iso_start, local_time, sizeof(local_time))) {
                    UPDATE_LABEL_SAFE(guider_ui.screen_label_10, label_start_time_main, local_time);
                    UPDATE_LABEL_SAFE(guider_ui.screen_label_29, label_start_time_summary, local_time);
                    // printf("Session start time (MQTT): %s\n", local_time);
                    is_mqtt_end_time_captured = false;
                }
            }
        }

        // Parse transaction_end_time
        char *end_field = strstr(payload_str, "\"transaction_end_time\":");
        if (end_field != NULL) {
            end_field += 23;  // Skip past "transaction_end_time":
            
            // Skip whitespace and quotes
            while (*end_field == ' ' || *end_field == '\t' || *end_field == '"') {
                end_field++;
            }
            
            char *end_quote = strchr(end_field, '"');
            if (end_quote != NULL && (end_quote - end_field) > 0) {
                char iso_end[64];
                int len = (end_quote - end_field) < 63 ? (end_quote - end_field) : 63;
                strncpy(iso_end, end_field, len);
                iso_end[len] = '\0';
                
                char local_time[32];
                if (parse_iso8601_to_local(iso_end, local_time, sizeof(local_time))) {
                    UPDATE_LABEL_SAFE(guider_ui.screen_label_30, label_end_time_buffer, local_time);
                    // printf("Session end time (MQTT): %s\n", local_time);
                    UPDATE_LABEL_SAFE(guider_ui.screen_label_10, label_start_time_main, "--:--:--");
                    UPDATE_LABEL_SAFE(guider_ui.screen_label_11, label_time_buffer, "--:--:--");
                    UPDATE_LABEL_SAFE(guider_ui.screen_label_3, label_energy_buffer_mqtt, "0.000 kWh");
                    is_mqtt_end_time_captured = true;
                }
            }
        }

        // Parse charged_energy_wh and transaction_duration_s for SOC and ETA
        char *energy_field = strstr(payload_str, "\"charged_energy_wh\":");
        char *duration_field_ptr = strstr(payload_str, "\"transaction_duration_s\":");
        
        int energy_wh = 0;
        int duration_seconds = 0;
        bool has_energy = false;
        bool has_duration = false;
        
        // ========== Parse charged_energy_wh ==========
        if (energy_field != NULL) {
            energy_field += 20;  // Skip past "charged_energy_wh":
            
            while (*energy_field == ' ' || *energy_field == '\t' || *energy_field == ':') {
                energy_field++;
            }
            
            if (*energy_field != '\0' && (isdigit((unsigned char)*energy_field) || *energy_field == '-')) {
                energy_wh = atoi(energy_field);
                if (energy_wh < 0) energy_wh = 0;
                if (energy_wh > 100000) energy_wh = 100000;
                has_energy = true;
                
                // Only update energy display if charging is not complete
                if (!charging_complete) {
                    mqtt_energy_kwh = energy_wh / 1000.0f;
                    snprintf(final_energy, sizeof(final_energy), "%.3f kWh", mqtt_energy_kwh);
                    
                    if (is_mqtt_end_time_captured) {
                        UPDATE_LABEL_SAFE(guider_ui.screen_label_3, label_energy_buffer_mqtt, "0.000 kWh");
                    } else {
                        UPDATE_LABEL_SAFE(guider_ui.screen_label_3, label_energy_buffer_mqtt, final_energy);
                        UPDATE_LABEL_SAFE(guider_ui.screen_label_28, label_energy_buffer_mqtt_summary, final_energy);
                    }
                }
            }
        }
        
        // ========== Parse discharged_energy_wh for direction detection ==========
        char *discharged_field = strstr(payload_str, "\"discharged_energy_wh\":");
        int discharged_wh = 0;
        
        if (discharged_field != NULL) {
            discharged_field += 23;  // Skip past "discharged_energy_wh":
            
            while (*discharged_field == ' ' || *discharged_field == '\t' || *discharged_field == ':') {
                discharged_field++;
            }
            
            if (*discharged_field != '\0' && (isdigit((unsigned char)*discharged_field) || *discharged_field == '-')) {
                discharged_wh = atoi(discharged_field);
                if (discharged_wh < 0) discharged_wh = 0;
            }
        }
        
        // ========== Determine charging direction (G2V vs V2G) ==========
        // ONLY update direction during active session - prevents overwriting "NA" after session ends
        lv_obj_add_flag(guider_ui.screen_img_19, LV_OBJ_FLAG_HIDDEN);
        if (!session_end_processed && (has_energy || discharged_wh > 0)) {
            if (energy_wh > discharged_wh) {
                // More energy charged than discharged = Grid to Vehicle
                snprintf(label_direction_buffer, sizeof(label_direction_buffer), "Direction: G2V");
                lv_img_set_src(guider_ui.screen_img_19, &_arrow_green_alpha_80x67);
                lv_obj_clear_flag(guider_ui.screen_img_19, LV_OBJ_FLAG_HIDDEN);
                lv_label_set_text_static(guider_ui.screen_label_55, label_direction_buffer);
            } else if (discharged_wh > energy_wh) {
                // More energy discharged than charged = Vehicle to Grid
                snprintf(label_direction_buffer, sizeof(label_direction_buffer), "Direction: V2G");
                lv_label_set_text_static(guider_ui.screen_label_55, label_direction_buffer);
                // Set red arrow for V2G (discharging)
                lv_img_set_src(guider_ui.screen_img_19, &_arrow_red_alpha_80x67);
                lv_obj_clear_flag(guider_ui.screen_img_19, LV_OBJ_FLAG_HIDDEN);

                // Display discharged energy on label_3 (same format as charged energy)
                if (!charging_complete) {
                    float discharged_kwh = discharged_wh / 1000.0f;
                    snprintf(final_energy, sizeof(final_energy), "%.3f kWh", discharged_kwh);

                    if (is_mqtt_end_time_captured) {
                        UPDATE_LABEL_SAFE(guider_ui.screen_label_3, label_energy_buffer_mqtt, "0.000 kWh");
                    } else {
                        UPDATE_LABEL_SAFE(guider_ui.screen_label_3, label_energy_buffer_mqtt, final_energy);
                        UPDATE_LABEL_SAFE(guider_ui.screen_label_28, label_energy_buffer_mqtt_summary, final_energy);
                    }
                }
            } else if (energy_wh == 0 && discharged_wh == 0) {
                // No energy flow yet
                snprintf(label_direction_buffer, sizeof(label_direction_buffer), "Direction: NA");
                lv_obj_add_flag(guider_ui.screen_img_19, LV_OBJ_FLAG_HIDDEN);
                lv_label_set_text_static(guider_ui.screen_label_55, label_direction_buffer);
            }
        }


        
        // ========== Parse transaction_duration_s ==========
        if (duration_field_ptr != NULL) {
            duration_field_ptr += 25;  // Skip past "transaction_duration_s":
            
            while (*duration_field_ptr == ' ' || *duration_field_ptr == '\t' || *duration_field_ptr == ':') {
                duration_field_ptr++;
            }
            
            if (*duration_field_ptr != '\0' && (isdigit((unsigned char)*duration_field_ptr) || *duration_field_ptr == '-')) {
                duration_seconds = atoi(duration_field_ptr);
                if (duration_seconds < 0) duration_seconds = 0;
                has_duration = true;
                
                // Update duration display for summary screen
                char duration_str[32];
                format_duration_seconds(duration_seconds, duration_str, sizeof(duration_str));
                UPDATE_LABEL_SAFE(guider_ui.screen_label_31, label_duration_buffer_mqtt, duration_str);
            }
        }
        
        // ========== Calculate Battery SOC ==========
        if (has_energy && initial_remaining_captured && initial_remaining_energy_wh > 0) {
            current_remaining_energy_wh = initial_remaining_energy_wh - (float)energy_wh;
            if (current_remaining_energy_wh < 0) {
                current_remaining_energy_wh = 0;
            }
            
            float current_soc = calculate_battery_soc(current_remaining_energy_wh);
            if (current_soc >= 0) {
                update_battery_display(current_soc);
                
                // Set flag when battery reaches 100%
                if (current_soc >= 100.0f) {
                    charging_complete = true;
                    printf("Battery fully charged - stopping energy updates\n");
                }
            }
        }
        
        // ========== Calculate Estimated Remaining Time ==========
        if (has_energy && has_duration && duration_seconds > 0 && initial_remaining_captured) {
            // Calculate instantaneous charging rate
            charging_rate_wh_per_sec = (float)energy_wh / (float)duration_seconds;
            
            // Update ETA with smoothed rate
            update_estimated_remaining_time(current_remaining_energy_wh, charging_rate_wh_per_sec);
        }

        // ========== Parse state for UI display ==========
        // Uses "state" field from session_info instead of "event" from session_event
        // EVerest EvseManager states: Unplugged, Disabled, Preparing, Reserved,
        //   AuthRequired, WaitingForEnergy, Charging, ChargingPausedEV,
        //   ChargingPausedEVSE, StoppingCharging, Finished, FinishedEV,
        //   FinishedEVSE, Replug, Unknown
        char *state_field = strstr(payload_str, "\"state\":");
        if (state_field != NULL) {
            state_field += 8;  // Skip past "state":

            // Skip whitespace and opening quote
            while (*state_field == ' ' || *state_field == '\t' || *state_field == '"') {
                state_field++;
            }

            // Find closing quote
            char *state_end = strchr(state_field, '"');

            if (state_end != NULL && (state_end - state_field) > 0) {
                char state_value[64] = {0};
                int slen = (state_end - state_field) < 63 ? (state_end - state_field) : 63;
                strncpy(state_value, state_field, slen);
                state_value[slen] = '\0';

                printf("=== SESSION INFO STATE: '%s' ===\n", state_value);

                const char *display_state = NULL;
                uint32_t state_color = 0xdcd1e5;  // Default gray

                if (strcmp(state_value, "Charging") == 0) {
                    display_state = "Charging";
                    state_color = 0xd0ff00;

                } else if (strcmp(state_value, "ChargingPausedEV") == 0 ||
                           strcmp(state_value, "ChargingPausedEVSE") == 0) {
                    display_state = state_value;
                    state_color = 0xFFA500;

                } else if (strcmp(state_value, "StoppingCharging") == 0) {
                    display_state = "StoppingCharging";
                    state_color = 0xFFFF00;

                } else if (strcmp(state_value, "Finished") == 0) {
                    display_state = "Finished";
                    state_color = 0x00FF00;

                } else if (strcmp(state_value, "FinishedEV") == 0) {
                    display_state = "FinishedEV";
                    state_color = 0x00FF00;

                } else if (strcmp(state_value, "FinishedEVSE") == 0) {
                    display_state = "FinishedEVSE";
                    state_color = 0x00FF00;

                } else if (strcmp(state_value, "Unplugged") == 0) {
                    display_state = "Unplugged";
                    state_color = 0xdcd1e5;

                } else if (strcmp(state_value, "Preparing") == 0) {
                    display_state = "Preparing";
                    state_color = 0xFFFF00;

                } else if (strcmp(state_value, "AuthRequired") == 0) {
                    display_state = "AuthRequired";
                    state_color = 0x00BFFF;

                } else if (strcmp(state_value, "WaitingForEnergy") == 0) {
                    display_state = "WaitingForEnergy";
                    state_color = 0x00BFFF;

                } else if (strcmp(state_value, "Replug") == 0) {
                    display_state = "Replug";
                    state_color = 0xFFFF00;

                } else if (strcmp(state_value, "Disabled") == 0) {
                    display_state = "Disabled";
                    state_color = 0xdcd1e5;

                } else if (strcmp(state_value, "Reserved") == 0) {
                    display_state = "Reserved";
                    state_color = 0xdcd1e5;

                } else {
                    display_state = state_value;
                    state_color = 0xdcd1e5;
                    printf(">>> UNKNOWN STATE - using default: '%s' <<<\n", state_value);
                }

                if (display_state != NULL) {
                    request_state_update(display_state, state_color);
                }
            }
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


                // Find "authorization_type" field in token for Auth Type
        char *auth_type_start = strstr(payload_str, "\"authorization_type\":");
        
        if (auth_type_start != NULL) {
            auth_type_start += 21;  // Skip past "authorization_type":
            
            // Skip whitespace and opening quote
            while (*auth_type_start == ' ' || *auth_type_start == '\t' || *auth_type_start == '"') {
                auth_type_start++;
            }
            
            // Find closing quote
            char *auth_type_end = strchr(auth_type_start, '"');
            
            if (auth_type_end != NULL && (auth_type_end - auth_type_start) > 0) {
                int auth_len = auth_type_end - auth_type_start;
                char auth_type[64];
                int len = auth_len < 63 ? auth_len : 63;
                strncpy(auth_type, auth_type_start, len);
                auth_type[len] = '\0';
                
                if (strcasecmp(auth_type, "RFID") == 0) {
                    snprintf(label_auth_type_buffer, sizeof(label_auth_type_buffer), "Auth: RFID");
                } else if (strcasecmp(auth_type, "PnC") == 0 ||
                           strcasecmp(auth_type, "PlugAndCharge") == 0) {
                    snprintf(label_auth_type_buffer, sizeof(label_auth_type_buffer), "Auth: PnC");
                } else if (strcasecmp(auth_type, "eMAID") == 0) {
                    snprintf(label_auth_type_buffer, sizeof(label_auth_type_buffer), "Auth: eMAID");
                } else if (strcasecmp(auth_type, "Central") == 0) {
                    snprintf(label_auth_type_buffer, sizeof(label_auth_type_buffer), "Auth: Central");
                } else if (strcasecmp(auth_type, "Local") == 0) {
                    snprintf(label_auth_type_buffer, sizeof(label_auth_type_buffer), "Auth: Local");
                } else if (strlen(auth_type) > 0) {
                    snprintf(label_auth_type_buffer, sizeof(label_auth_type_buffer), "Auth: %s", auth_type);
                } else {
                    snprintf(label_auth_type_buffer, sizeof(label_auth_type_buffer), "Auth: NA");
                }
            } else {
                snprintf(label_auth_type_buffer, sizeof(label_auth_type_buffer), "Auth: NA");
            }
        } else {
            snprintf(label_auth_type_buffer, sizeof(label_auth_type_buffer), "Auth: NA");
        }
        
        lv_label_set_text_static(guider_ui.screen_label_62, label_auth_type_buffer);


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

/**
 * Pause charging session using direct EVerest API
 * Topic: everest_api/evse_manager_1/cmd/pause_charging
 * Payload: empty string
 * 
 * Works for: IEC 61851-1 (Basic Charging)
 * Note: ISO 15118 uses HLC and may require different handling
 */
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
  
  // ============================================
    // DIRECT EVEREST API (No Node-RED dependency)
    // ============================================
    pubmsg.payload = "";  // Empty payload for direct API
    pubmsg.payloadlen = 0;
    pubmsg.qos = QOS; 
    pubmsg.retained = 0;
    
    MQTTClient_publishMessage(client, EVSE_PAUSE_TOPIC, &pubmsg, NULL); 
    printf("Pause command sent to: %s\n", EVSE_PAUSE_TOPIC);
    
    active_session = false;
}

/**
 * Resume charging session using direct EVerest API
 * Topic: everest_api/evse_manager_1/cmd/resume_charging
 * Payload: empty string
 * 
 * Works for: IEC 61851-1 (Basic Charging)
 * Note: ISO 15118 uses HLC and may require different handling
 */
void resume_charging(){
    printf("\n========================================\n");
    printf("=== RESUME_CHARGING CALLED ===\n");
    printf("========================================\n");
    
    // ============================================
    // DIRECT EVEREST API (No Node-RED dependency)
    // ============================================
    pubmsg.payload = "";  // Empty payload for direct API
    pubmsg.payloadlen = 0;
    pubmsg.qos = QOS; 
    pubmsg.retained = 0;
    
    MQTTClient_publishMessage(client, EVSE_RESUME_TOPIC, &pubmsg, NULL); 
    printf("Resume command sent to: %s\n", EVSE_RESUME_TOPIC);
    
    // Reset pause time captured flag on resume
    pause_time_captured = false;
    
    printf("========================================\n\n");
}

void increase_battery_level(){
    char battery_level_to_str[50];
    int battery_level_to_int;
    char power_str[20];
    int power_int;

    // Get current time
    time_t current_time = time(NULL);
    
    // Only update if enough time has passed (1 second interval)
    if (difftime(current_time, last_update_time) < UPDATE_INTERVAL_SECONDS) {
        return;
    }
    
    // Update the last update time
    last_update_time = current_time;

    // Check if charging is active and battery below limit
    if (active_session && (battery_level < max_limit)) {
        set_paused = 1;
        
        // Format current battery value for display
        sprintf(battery_level_to_str, "%.1f", battery_level);
        battery_level_to_int = (int)battery_level;
        
        UPDATE_LABEL_SAFE(guider_ui.screen_label_38, label_battery_buffer, battery_level_to_str);
        UPDATE_LABEL_SAFE(guider_ui.screen_label_19, label_battery_buffer, battery_level_to_str);
        lv_bar_set_value(guider_ui.screen_bar_2, battery_level_to_int, LV_ANIM_OFF);

        // Update power meter display
        if (mqtt_power_kw > 0) {
            power_int = (int)mqtt_power_kw;
            sprintf(power_str, "%.0f", mqtt_power_kw);
        } else {
            power_int = 0;
            sprintf(power_str, "0");
        }
        lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, power_int);
        UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, power_str);
        
        // NOTE: ETA is calculated in session_info handler (Feature 2)
        
    } else {
        // Battery reached limit or not charging - trigger pause
        if (set_paused == 1) {
            printf("Automatic pause triggered (battery limit reached)\n");
            pause_charging();
            lv_obj_clear_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
            UPDATE_LABEL_SAFE(guider_ui.screen_label_11, label_duration_buffer, "--:--:--");
            lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, 0);
            UPDATE_LABEL_SAFE(guider_ui.screen_label_25, label_power_buffer, "0");
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
            // unplug(); 
            UPDATE_LABEL_SAFE(guider_ui.screen_label_10, label_time_buffer, "--:--:--");
            lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
            lv_obj_add_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
    		lv_obj_add_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(guider_ui.screen_img_19, LV_OBJ_FLAG_HIDDEN);
    		lv_obj_add_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
    		lv_obj_add_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
			break;
		}
		case 1:
		{
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
