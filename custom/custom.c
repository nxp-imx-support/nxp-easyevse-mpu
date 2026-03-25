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
 *      TYPEDEFS
 **********************/

/**********************
 *  STATIC PROTOTYPES
 **********************/

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
    lv_label_set_text(guider_ui.screen_label_41, ip_address);
    lv_label_set_text(guider_ui.screen_label_45, network_type);
    
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
        lv_obj_clear_flag(guider_ui.screen_cont_4, LV_OBJ_FLAG_HIDDEN);
        printf("MQTT timeout - showing cont_4 overlay (EVerest not running)\n");
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

  // setenv("LD_LIBRARY_PATH","/usr/local/lib64",1);
  const char *location = getenv("LOCATION");
  if (location != NULL){
    printf("PATH: %s", location);
    lv_label_set_text(guider_ui.screen_label_7, (char *)location);
  }else{
    lv_label_set_text(guider_ui.screen_label_7, "NXP Plot 1");
  } 
  
  // ADD THIS INITIALIZATION FOR EVSE ID
  // Initialize EVSE ID label with default "NA"
  lv_label_set_text(guider_ui.screen_label_43, "EVSE ID: NA");
//   printf("EVSE ID initialized to 'EVSE ID: NA'\n");
  
  // ADD THIS INITIALIZATION FOR EV ID
  // Initialize EV ID label with formatted default
  lv_label_set_text(guider_ui.screen_label_44, "EV ID: NA");
//   printf("EV ID initialized to 'EV ID: NA'\n");

  // Initialize ISO 15118 Mode label
  lv_label_set_text(guider_ui.screen_label_52, "ISO Mode: NA");
//   printf("ISO 15118 Mode initialized to: ISO Mode: NA\n");
  
  // Initialize ISO 15118 Protocol label
  lv_label_set_text(guider_ui.screen_label_53, "Protocol: NA");
//   printf("ISO 15118 Protocol initialized to: Protocol: NA\n");
  
  // Initialize ISO 15118 Voltage label
  lv_label_set_text(guider_ui.screen_label_54, "Voltage: NA");
//   printf("ISO 15118 Voltage initialized to: Voltage: NA\n");
  
  // Initialize ISO 15118 Charging Direction label
  lv_label_set_text(guider_ui.screen_label_55, "Direction: NA");
//   printf("ISO 15118 Direction initialized to: Direction: NA\n");
  // Initialize Sigboard Connection Type label
  lv_label_set_text(guider_ui.screen_label_56, "Sigboard: NA");
//   printf("Sigboard Connection initialized to: Sigboard: NA\n");

  // Initialize NFC Card UID label
  lv_label_set_text(guider_ui.screen_label_57, "UID: NA");
//   printf("NFC Card UID initialized to: UID: NA\n");

  // Initialize NFC Card Type label
  lv_label_set_text(guider_ui.screen_label_58, "Type: NA");
//   printf("NFC Card Type initialized to: Type: NA\n");

  // Initialize NFC Card Status label
  lv_label_set_text(guider_ui.screen_label_59, "Status: NA");
  lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
//   printf("NFC Card Status initialized to: Status: NA\n");

  // Initialize Current L1 display
  lv_label_set_text(guider_ui.screen_label_60, "0.0 A");
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
    lv_label_set_text(guider_ui.screen_label_41, ip_address);
    // printf("Machine IP set to label_41: %s\n", ip_address);
    
    // Get and display network type
    get_network_type(interface_name, network_type, sizeof(network_type));
    lv_label_set_text(guider_ui.screen_label_45, network_type);
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
  
//   printf("DEBUG: hour_24 = %d\n", hour_24);
//   printf("DEBUG: am_pm string = '%s'\n", am_pm);
//   printf("DEBUG: am_pm[0] = '%c', am_pm[1] = '%c'\n", am_pm[0], am_pm[1]);
  
  // Convert to 12-hour format
  int hour_12 = hour_24 % 12;
  if (hour_12 == 0) hour_12 = 12; // Handle midnight and noon
  
  sprintf(hour, "%02d", hour_12);
  sprintf(minutes, "%02d", timeinfo->tm_min);
  sprintf(seconds, "%02d", timeinfo->tm_sec);
  
//   printf("Current local time and date: %s", asctime(timeinfo));
//   printf("Time: %s:%s:%s %s (24h: %d)\n", hour, minutes, seconds, am_pm, hour_24);
}


void set_screen_digital_clock_1(){
  update_time();
  screen_digital_clock_1_hour_value = atoi(hour);
  screen_digital_clock_1_min_value = atoi(minutes);
  screen_digital_clock_1_sec_value = atoi(seconds);
  strcpy(screen_digital_clock_1_meridiem, am_pm);
}

int messageArrived(void *context, char *topic, int topicLen, MQTTClient_message *message) {
    // printf("Received: %s -> %.*s\n", topic, message->payloadlen, (char *)message->payload);

    // Update last message time
    last_mqtt_message_time = time(NULL);
    
    // Hide cont_4 when MQTT messages are coming (EVerest is running)
    lv_obj_add_flag(guider_ui.screen_cont_4, LV_OBJ_FLAG_HIDDEN);
    
    if (strcmp(topic,"everest_external/nodered/1/state/state_string") == 0){
       lv_label_set_text(guider_ui.screen_label_1, (char *)message->payload);
       lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xdcd1e5), LV_PART_MAIN|LV_STATE_DEFAULT);
       lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_arial_30, 0);
      if (
          strcmp((char *)message->payload, "StoppingCharging") == 0 ||
          strcmp((char *)message->payload, "Finished") == 0 ||
          strcmp((char *)message->payload, "Idle") == 0
      ) {
          
          // Skip if already processed to prevent duplicate processing
          if (session_end_processed) {
            //   printf("\n>>> Session end already processed, skipping: %s <<<\n\n", 
            //          (char *)message->payload);
              lv_label_set_text(guider_ui.screen_label_1, "Unplugged");
              lv_label_set_text(guider_ui.screen_label_57, "UID: NA");
              lv_label_set_text(guider_ui.screen_label_58, "Type: NA");
              lv_label_set_text(guider_ui.screen_label_59, "Status: NA");
              lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
              MQTTClient_freeMessage(&message);
              MQTTClient_free(topic);
              return 1;
          }
          
          // Mark as processed immediately
          session_end_processed = true;
          
        //   printf("\n========================================\n");
        //   printf("=== SESSION END: %s (PROCESSING) ===\n", (char *)message->payload);
        //   printf("========================================\n");
          
          // Get current system time
          time_t rawtime;
          struct tm * timeinfo;
          time(&rawtime);
          timeinfo = localtime(&rawtime);
        //   printf("System time NOW: %02d:%02d:%02d\n", 
        //          timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
          
        //   printf("\nSession state:\n");
        //   printf("  pause_time_captured = %d\n", pause_time_captured);
        //   printf("  start_time_captured = %d\n", start_time_captured);
        //   printf("  is_session_started = %d\n", is_session_started);
          
        //   if (pause_time_captured) {
        //       printf("\nStored pauseTime:\n");
        //       printf("  %02d:%02d:%02d %s\n", 
        //              pauseTime.hours, pauseTime.minutes, pauseTime.seconds,
        //              (pauseTime.ampm == 'A') ? "AM" : "PM");
        //   }
          
        //   if (start_time_captured) {
        //       printf("\nStored startTime:\n");
        //       printf("  %02d:%02d:%02d %s\n", 
        //              startTime.hours, startTime.minutes, startTime.seconds,
        //              (startTime.ampm == 'A') ? "AM" : "PM");
        //   }
        //   printf("========================================\n\n");
          
          active_session = false;
          start_time_captured = false;  // Keep this here
          // pause_time_captured will be reset later
          
          lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xdcd1e5), LV_PART_MAIN|LV_STATE_DEFAULT);
          lv_img_set_src(guider_ui.screen_img_2, &_Car_Unplugged_0_alpha_1277x797);
          
          // migrated_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_
          lv_label_set_text(guider_ui.screen_label_10, "--:--:--");
          lv_label_set_text(guider_ui.screen_label_1, "Unplugged");
          lv_obj_add_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
          // Reset NFC Card UID and Type (always, regardless of session state)
          lv_label_set_text(guider_ui.screen_label_57, "UID: NA");
          lv_label_set_text(guider_ui.screen_label_58, "Type: NA");
          lv_label_set_text(guider_ui.screen_label_59, "Status: NA");
          lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
          char string_time_out[20];
          char diff_time[20];

            //   printf("\n========================================\n");
            //   printf("=== CALCULATING END TIME ===\n");
            //   printf("========================================\n");
            //   printf("pause_time_captured = %d\n", pause_time_captured);

      // Use pause time as end time if session was paused, otherwise use current time
      if (pause_time_captured) {
          endTime = pauseTime;
        //   printf("\n✓ Using PAUSE time as end time\n");
        //   printf("  pauseTime: %02d:%02d:%02d %s\n", 
        //          pauseTime.hours, pauseTime.minutes, pauseTime.seconds,
        //          (pauseTime.ampm == 'A') ? "AM" : "PM");
        //   printf("  endTime: %02d:%02d:%02d %s\n", 
        //          endTime.hours, endTime.minutes, endTime.seconds,
        //          (endTime.ampm == 'A') ? "AM" : "PM");
      } else {
          set_screen_digital_clock_1();
          endTime.hours = atoi(hour);
          endTime.minutes = atoi(minutes);
          endTime.seconds = atoi(seconds);
          endTime.ampm = (strcmp(am_pm, "AM") == 0) ? 'A' : 'P';
        //   printf("\n✗ Using CURRENT time as end time\n");
        //   printf("  Current: %s:%s:%s %s\n", hour, minutes, seconds, am_pm);
        //   printf("  endTime: %02d:%02d:%02d %s\n", 
        //          endTime.hours, endTime.minutes, endTime.seconds,
        //          (endTime.ampm == 'A') ? "AM" : "PM");
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

//   printf("\nDuration calculation:\n");
//   printf("  startTime: %02d:%02d:%02d %s (%d seconds)\n", 
//          startTime.hours, startTime.minutes, startTime.seconds,
//          (startTime.ampm == 'A') ? "AM" : "PM", startTimeInSeconds);
//   printf("  endTime: %02d:%02d:%02d %s (%d seconds)\n", 
//          endTime.hours, endTime.minutes, endTime.seconds,
//          (endTime.ampm == 'A') ? "AM" : "PM", endTimeInSeconds);
//   printf("  Duration: %02d:%02d:%02d (%d seconds)\n", 
//          diffTime.hours, diffTime.minutes, diffTime.seconds, diffInSeconds);
          
  // Format end time string
  snprintf(string_time_out, sizeof(string_time_out), "%02d:%02d:%02d %s", 
           endTime.hours, endTime.minutes, endTime.seconds,
           (endTime.ampm == 'A') ? "AM" : "PM");
  snprintf(diff_time, sizeof(diff_time), "%02d:%02d:%02d", 
           diffTime.hours, diffTime.minutes, diffTime.seconds);

//   printf("\nFormatted strings:\n");
//   printf("  End time (label_30): %s\n", string_time_out);
//   printf("  Duration (label_31): %s\n", diff_time);
//   printf("========================================\n\n");

  lv_label_set_text(guider_ui.screen_label_30, string_time_out);
  lv_label_set_text(guider_ui.screen_label_31, diff_time);
          if (is_session_started){
            lv_obj_clear_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
            battery_level = 20.0;
            totalKWattHr = 0.000;
            mqtt_power_kw = 0.0f;
            mqtt_energy_kwh = 0.0f;
            lv_label_set_text(guider_ui.screen_label_38, "20.0");
            lv_label_set_text(guider_ui.screen_label_19, "20.0");
            lv_label_set_text(guider_ui.screen_label_3, "0.0kWh");
            lv_label_set_text(guider_ui.screen_label_11, "--:--:--");
            lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, 0);
            lv_label_set_text(guider_ui.screen_label_25, "0");
            lv_bar_set_value(guider_ui.screen_bar_2, 20, LV_ANIM_OFF);
            lv_label_set_text(guider_ui.screen_label_57, "UID: NA");
            lv_label_set_text(guider_ui.screen_label_58, "Type: NA");
            lv_label_set_text(guider_ui.screen_label_59, "Status: NA");
            lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);

            is_session_started = false;
            printf("Session values reset (is_session_started was true)\n");
          }

        //   printf("\n=== RESETTING FLAGS ===\n");
        //   printf("Before reset - pause_time_captured = %d\n", pause_time_captured);
          pause_time_captured = false;
        //   printf("After reset - pause_time_captured = %d\n", pause_time_captured);
        //   printf("=======================\n\n");
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
        //   printf("Pause time captured: %s:%s:%s %s\n", hour, minutes, seconds, am_pm);
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
          lv_label_set_text(guider_ui.screen_label_1, "Plugged in");
          sleep(1);
          lv_label_set_text(guider_ui.screen_label_1, "Wait for Auth");
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
              
              lv_label_set_text(guider_ui.screen_label_10, string_time);
              lv_label_set_text(guider_ui.screen_label_29, string_time);
              
              start_time_captured = true;
            //   printf("Start time captured at Charging state: %s\n", string_time);
          }
      }      
      if ((strcmp((char *)message->payload,"PrepareCharging") == 0) && (is_new_session)){
        lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_arial_30, 0);
        lv_label_set_text(guider_ui.screen_label_1, "Authenticating...");
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
        // lv_label_set_text(guider_ui.screen_label_1, "Unplugged");
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
        // lv_label_set_text(guider_ui.screen_label_30, string_time_out);
        // lv_label_set_text(guider_ui.screen_label_31, diff_time);
        // if (is_session_started){
        //   lv_obj_clear_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
        //   is_session_started = false;
        // }
      }
      
    } else if (strcmp(topic,"everest_external/nodered/1/state/temperature") == 0){
      // lv_label_set_text(guider_ui.screen_label_25, topic);
      char *delim = ".";
      char before_dot[20], after_dot[20];
      char *token;
      token = strtok((char *)message->payload, delim);
      strcpy(before_dot, token);
      
      lv_label_set_text(guider_ui.screen_label_4, token);
    } else if (strcmp(topic,"everest_external/nodered/1/powermeter/totalKw") == 0){
      // lv_label_set_text(guider_ui.screen_label_25, topic);
      //move to increare_batery_level 
      // lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, atoi(message->payload));
      // lv_label_set_text_fmt(gui->speed_label_digit, "%"LV_PRId32, speed);
      //lv_label_set_text(guider_ui.screen_label_25, (char *)message->payload);
    //   mqtt_power_kw = atof((char *)message->payload);
    //   printf("Received totalKw: %.2f\n", mqtt_power_kw);
      //move to increare_batery_level lv_label_set_text(guider_ui.screen_label_25, (char *)message->payload);

       int result = system("ping -c 1 8.8.8.8 -W 2 2>/dev/null 1>/dev/null");
      //move to increare_batery_level 
      //lv_label_set_text(guider_ui.screen_label_25, (char *)message->payload);
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
      // lv_label_set_text(guider_ui.screen_label_3, (char *)message->payload);
      // strcpy(final_energy,(char *)message->payload);
      mqtt_energy_kwh = atof((char *)message->payload);
      strcpy(final_energy, (char *)message->payload);
    //   printf("Received totalKWattHr: %.3f\n", mqtt_energy_kwh);

    //   printf("this is blank");
      // will uncomment with actual values
    } else if (strcmp(topic, "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/evse_id") == 0) {
      char evse_id_display[128];
    
      // Check if payload is empty or null
      if (message->payloadlen > 0 && message->payload != NULL) {
          char *payload_str = (char *)message->payload;
          
          // The payload is a simple string value like "RO*NXP*E1234567*1"
          // Remove quotes if present
          char evse_id[128] = {0};
          int idx = 0;
          
          for (int i = 0; i < message->payloadlen && i < 127; i++) {
              char c = payload_str[i];
              // Skip quotes
              if (c != '"' && c != '\0') {
                  evse_id[idx++] = c;
              }
          }
          evse_id[idx] = '\0';
          
          // Check if we got a valid EVSE ID
          if (strlen(evse_id) > 0) {
              snprintf(evse_id_display, sizeof(evse_id_display), "EVSE ID: %s", evse_id);
              lv_label_set_text(guider_ui.screen_label_43, evse_id_display);
              printf("EVSE ID: %s\n", evse_id);
          } else {
              lv_label_set_text(guider_ui.screen_label_43, "EVSE ID: NA");
              printf("EVSE ID: NA (empty after parsing)\n");
          }
      } else {
          lv_label_set_text(guider_ui.screen_label_43, "EVSE ID: NA");
          printf("EVSE ID: NA (empty payload)\n");
      }
    
    } else if (strcmp(topic, "everest_external/nodered/1/ev/ev_id") == 0) {
      char ev_id_display[128];
      
      // Check if payload is empty or null
      if (message->payloadlen > 0 && message->payload != NULL) {
          snprintf(ev_id_display, sizeof(ev_id_display), "EV ID: %s", (char *)message->payload);
          lv_label_set_text(guider_ui.screen_label_44, ev_id_display);
          printf("EV ID: %s\n", (char *)message->payload);
      } else {
          lv_label_set_text(guider_ui.screen_label_44, "EV ID: NA");
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
            snprintf(iso_mode_display, sizeof(iso_mode_display), "ISO Mode: %c", toupper(mode));
            lv_label_set_text(guider_ui.screen_label_52, iso_mode_display);
            printf("ISO 15118 Mode: %c\n", toupper(mode));
        } else {
            lv_label_set_text(guider_ui.screen_label_52, "ISO Mode: NA");
            printf("ISO 15118 Mode: Invalid mode '%s'\n", (char *)message->payload);
        }
    } else {
        lv_label_set_text(guider_ui.screen_label_52, "ISO Mode: NA");
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
            snprintf(protocol_display, sizeof(protocol_display), "Protocol: Unknown");
        } else if (strstr(protocol, "15118-2") != NULL || 
                   strstr(protocol, "15118_2") != NULL ||
                   strcasecmp(protocol, "ISO15118-2") == 0 ||
                   strcasecmp(protocol, "ISO 15118-2") == 0) {
            snprintf(protocol_display, sizeof(protocol_display), "Protocol: ISO 15118-2");
        } else if (strstr(protocol, "15118-20") != NULL || 
                   strstr(protocol, "15118_20") != NULL ||
                   strcasecmp(protocol, "ISO15118-20") == 0 ||
                   strcasecmp(protocol, "ISO 15118-20") == 0) {
            snprintf(protocol_display, sizeof(protocol_display), "Protocol: ISO 15118-20");
        } else if (strcasecmp(protocol, "IEC61851-1") == 0 ||
                   strcasecmp(protocol, "IEC 61851-1") == 0 ||
                   strcasecmp(protocol, "IEC61851") == 0 ||
                   strcasecmp(protocol, "Basic") == 0 ||
                   strstr(protocol, "61851") != NULL) {
            snprintf(protocol_display, sizeof(protocol_display), "Protocol: Basic");
        } else if (strlen(protocol) > 0) {
            // Display the raw protocol value if not empty and unknown
            snprintf(protocol_display, sizeof(protocol_display), "Protocol: %s", protocol);
        } else {
            snprintf(protocol_display, sizeof(protocol_display), "Protocol: NA");
        }
        
        lv_label_set_text(guider_ui.screen_label_53, protocol_display);
        printf("Selected Protocol: %s\n", protocol);
    } else {
        lv_label_set_text(guider_ui.screen_label_53, "Protocol: NA");
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
                snprintf(voltage_display, sizeof(voltage_display), "Voltage: %d V", (int)voltage);
            } else {
                // Display with 1 decimal place (e.g., "Voltage: 400.5 V")
                snprintf(voltage_display, sizeof(voltage_display), "Voltage: %.1f V", voltage);
            }
            lv_label_set_text(guider_ui.screen_label_54, voltage_display);
            printf("ISO 15118 Voltage: %.1f V\n", voltage);
        } else {
            // Out of range
            lv_label_set_text(guider_ui.screen_label_54, "Voltage: NA");
            printf("ISO 15118 Voltage: Out of range (%.1f V)\n", voltage);
        }
    } else {
        lv_label_set_text(guider_ui.screen_label_54, "Voltage: NA");
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
            snprintf(direction_display, sizeof(direction_display), "Direction: G2V");
            lv_label_set_text(guider_ui.screen_label_55, direction_display);
            printf("ISO 15118 Direction: G2V (Grid to Vehicle - Charging)\n");
        }
        // Check for V2G (Vehicle to Grid - Discharging)
        else if (strcasecmp(direction, "V2G") == 0 ||
                      strcasecmp(direction, "Vehicle2Grid") == 0 ||
                      strcasecmp(direction, "VehicleToGrid") == 0 ||
                      strcasecmp(direction, "Vehicle to Grid") == 0 ||
                      strstr(direction, "V2G") != NULL ||
                      strstr(direction, "v2g") != NULL) {
            snprintf(direction_display, sizeof(direction_display), "Direction: V2G");
            lv_label_set_text(guider_ui.screen_label_55, direction_display);
            printf("ISO 15118 Direction: V2G (Vehicle to Grid - Discharging)\n");
        }
        // Unknown or invalid direction
        else {
            lv_label_set_text(guider_ui.screen_label_55, "Direction: NA");
            printf("ISO 15118 Direction: Unknown (%s)\n", direction);
        }
    } else {
        lv_label_set_text(guider_ui.screen_label_55, "Direction: NA");
        printf("ISO 15118 Direction: NA (empty payload)\n");
    }
  
  } else if (strcmp(topic, "everest_external/nodered/1/sigboard/connection_type") == 0) {
    char connection_display[32];
      
    if (message->payloadlen > 0 && message->payload != NULL) {
        char *connection = (char *)message->payload;
          
        if (strcasecmp(connection, "Serial") == 0 ||
                 strcasecmp(connection, "UART") == 0 ||
                 strstr(connection, "serial") != NULL ||
                 strstr(connection, "uart") != NULL) {
            snprintf(connection_display, sizeof(connection_display), "Sigboard: Serial");
            lv_label_set_text(guider_ui.screen_label_56, connection_display);
            printf("Sigboard Connection: Serial/UART\n");
        }
        // Check for I2C
        else if (strcasecmp(connection, "I2C") == 0 ||
                 strstr(connection, "i2c") != NULL ||
                 strstr(connection, "I2C") != NULL) {
            snprintf(connection_display, sizeof(connection_display), "Sigboard: I2C");
            lv_label_set_text(guider_ui.screen_label_56, connection_display);
            printf("Sigboard Connection: I2C\n");
        }
        // Check for SPI
        else if (strcasecmp(connection, "SPI") == 0 ||
                 strstr(connection, "spi") != NULL ||
                 strstr(connection, "SPI") != NULL) {
            snprintf(connection_display, sizeof(connection_display), "Sigboard: SPI");
            lv_label_set_text(guider_ui.screen_label_56, connection_display);
            printf("Sigboard Connection: SPI\n");
        }
        // Unknown or invalid connection type
        else {
            lv_label_set_text(guider_ui.screen_label_56, "Sigboard: NA");
            printf("Sigboard Connection: Unknown (%s)\n", connection);
        }
    } else {
        lv_label_set_text(guider_ui.screen_label_56, "Sigboard: NA");
        printf("Sigboard Connection: NA (empty payload)\n");
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
                snprintf(uid_display, sizeof(uid_display), "UID: %s", uid_formatted);
            } else {
                snprintf(uid_display, sizeof(uid_display), "UID: NA");
            }
        } else {
            snprintf(uid_display, sizeof(uid_display), "UID: NA");
        }
    } else {
        snprintf(uid_display, sizeof(uid_display), "UID: NA");
    }
    
    lv_label_set_text(guider_ui.screen_label_57, uid_display);
    
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
                snprintf(type_display, sizeof(type_display), "Type: Local");
            } else if (strcasecmp(card_type, "ISO14443") == 0 || 
                       strcasestr(card_type, "14443") != NULL) {
                snprintf(type_display, sizeof(type_display), "Type: ISO14443");
            } else if (strcasestr(card_type, "MIFARE") != NULL) {
                snprintf(type_display, sizeof(type_display), "Type: MIFARE");
            } else if (strcasestr(card_type, "NTAG") != NULL) {
                snprintf(type_display, sizeof(type_display), "Type: NTAG");
            } else if (strcasecmp(card_type, "Central") == 0) {
                snprintf(type_display, sizeof(type_display), "Type: Central");
            } else if (strcasecmp(card_type, "eMAID") == 0) {
                snprintf(type_display, sizeof(type_display), "Type: eMAID");
            } else if (strcasecmp(card_type, "ISO15693") == 0 || 
                       strcasestr(card_type, "15693") != NULL) {
                snprintf(type_display, sizeof(type_display), "Type: ISO15693");
            } else {
                // Display the raw type value if unknown
                snprintf(type_display, sizeof(type_display), "Type: %s", card_type);
            }
        } else {
            snprintf(type_display, sizeof(type_display), "Type: NA");
        }
    } else {
        snprintf(type_display, sizeof(type_display), "Type: NA");
    }
    
    lv_label_set_text(guider_ui.screen_label_58, type_display);
    
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
                snprintf(status_display, sizeof(status_display), "Status: Accepted");
                lv_label_set_text(guider_ui.screen_label_59, status_display);
                // Set text color to green
                lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0x00FF00), LV_PART_MAIN|LV_STATE_DEFAULT);
            }
            // Check for Rejected/Denied status
            else if (strcasecmp(card_status, "Rejected") == 0 ||
                     strcasecmp(card_status, "Denied") == 0 ||
                     strcasecmp(card_status, "Invalid") == 0 ||
                     strcasecmp(card_status, "Blocked") == 0 ||
                     strcasecmp(card_status, "Failed") == 0) {
                snprintf(status_display, sizeof(status_display), "Status: Rejected");
                lv_label_set_text(guider_ui.screen_label_59, status_display);
                // Set text color to red
                lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xFF0000), LV_PART_MAIN|LV_STATE_DEFAULT);
            }
            // Unknown status - display as-is
            else {
                snprintf(status_display, sizeof(status_display), "Status: %s", card_status);
                lv_label_set_text(guider_ui.screen_label_59, status_display);
                // Set text color to default gray/white
                lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
            }
        } else {
            snprintf(status_display, sizeof(status_display), "Status: NA");
            lv_label_set_text(guider_ui.screen_label_59, status_display);
            lv_obj_set_style_text_color(guider_ui.screen_label_59, lv_color_hex(0xDCD1E5), LV_PART_MAIN|LV_STATE_DEFAULT);
        }
    } else {
        snprintf(status_display, sizeof(status_display), "Status: NA");
        lv_label_set_text(guider_ui.screen_label_59, status_display);
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
                snprintf(current_display, sizeof(current_display), "%.1f A", current_l1);
                
                // Update label_60
                lv_label_set_text(guider_ui.screen_label_60, current_display);
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
void get_mqtt_state_for_evse()
{
  
  // lv_label_set_text(guider_ui.pageStatic_label_1, PAYLOAD);
  MQTTClient_create(&client, ADDRESS, CLIENTID, MQTTCLIENT_PERSISTENCE_NONE, NULL); 
  MQTTClient_setCallbacks(client, NULL, NULL, messageArrived, NULL);

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
      return;
  } else {
      printf("Connected to MQTT broker ...\n");
     // lv_label_set_text(guider_ui.pageStatic_label_1, "");
  }

  /////////////////////////Old subscriptions START
  /* Introduced delay to avoid subscription lost
     due to Timing/race conditoin issue
   */
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/powermeter/totalKWattHr", QOS);
// //   printf("Subscribe totalKWattHr: %d\n", rc);
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/powermeter/totalKw", QOS);
// //   printf("Subscribe totalKw: %d\n", rc);
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/state/temperature", QOS);
// //   printf("Subscribe temperature: %d\n", rc);
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/state/state_string", QOS);
// //   printf("Subscribe state_string: %d\n", rc);
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_api/ocpp/var/connection_status", QOS);
// //   printf("Subscribe CSMS connection_status: %d\n", rc);
// //   printf("Subscribe csms_status: %d\n", rc);
//   // ADD THIS FOR EVSE ID
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/evse_id", QOS);
// //   printf("Subscribe evse_id: %d\n", rc);
//   // ADD THIS FOR EV ID
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/ev/ev_id", QOS);
// //   printf("Subscribe ev_id: %d\n", rc);
//   // ADD THIS FOR BATTERY LEVEL
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/ev/battery_level", QOS);
// //   printf("Subscribe battery_level: %d\n", rc);
//   // ADD THIS FOR ISO 15118 MODE
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/iso15118/mode", QOS);
// //   printf("Subscribe iso15118_mode: %d\n", rc);
//   // ADD THIS FOR ISO 15118 PROTOCOL
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_api/1/evse_manager_consumer/evse_manager_api/e2m/selected_protocol", QOS);
// //   printf("Subscribe iso15118_protocol: %d\n", rc);
//   // ADD THIS FOR ISO 15118 VOLTAGE
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/iso15118/voltage", QOS);
// //   printf("Subscribe iso15118_voltage: %d\n", rc);
//   // ADD THIS FOR ISO 15118 CHARGING DIRECTION
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/iso15118/direction", QOS);
// //   printf("Subscribe iso15118_direction: %d\n", rc);
//   // ADD THIS FOR SIGBOARD CONNECTION TYPE
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/sigboard/connection_type", QOS);
// //   printf("Subscribe sigboard_connection_type: %d\n", rc);
//   // ADD THIS FOR NFC CARD UID
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_api/1/auth_consumer/auth_api/e2m/token_validation_status", QOS);
// //   printf("Subscribe nfc_card_uid: %d\n", rc);
//   // ADD THIS FOR NFC CARD TYPE
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/nfc/card_type", QOS);
// //   printf("Subscribe nfc_card_type: %d\n", rc);
//   // ADD THIS FOR NFC CARD STATUS
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_external/nodered/1/nfc/card_status", QOS);
// //   printf("Subscribe nfc_card_status: %d\n", rc);
//   // ADD THIS FOR MAX CURRENT
//   usleep(100000); // 100ms delay
//   rc = MQTTClient_subscribe(client, "everest_api/evse_manager_1/var/powermeter", QOS);
//   printf("Subscribe powermeter: %d\n", rc);

  // MQTTClient_subscribe(client, "everest_external/nodered/1/cmd/set_max_current", QOS); 

  // MQTTClient_message pubmsg = MQTTClient_message_initializer; 
  // set_max_temp();
  /////////////////////////Old subscriptions END
// *******************************************************************************************

  /////////////////////////replace subscription starts
    // Subscribe to all topics (no delays needed - MQTT client handles queuing)
    const char* topics[] = {
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
        "everest_external/nodered/1/sigboard/connection_type",
        "everest_api/1/auth_consumer/auth_api/e2m/token_validation_status",
        // "everest_external/nodered/1/nfc/card_type",
        // "everest_external/nodered/1/nfc/card_status",
        "everest_api/evse_manager_1/var/powermeter"
    };

    int topic_count = sizeof(topics) / sizeof(topics[0]);

    for (int i = 0; i < topic_count; i++) {
        rc = MQTTClient_subscribe(client, topics[i], QOS);
        if (rc != MQTTCLIENT_SUCCESS) {
            printf("Failed to subscribe to %s: %d\n", topics[i], rc);
        }
    }

    printf("Subscribed to %d MQTT topics\n", topic_count);

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

  lv_label_set_text(guider_ui.screen_label_27, final_energy);
  lv_label_set_text(guider_ui.screen_label_28, final_energy);
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
    lv_snprintf(buf, sizeof(buf), "MAX: %d%", (char)lv_slider_get_value(slider));
    lv_snprintf(publish_buffer, sizeof(buf), "%d%", (int)lv_slider_get_value(slider));
    lv_label_set_text(guider_ui.screen_label_6, buf);
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
     
    
    lv_label_set_text(guider_ui.screen_label_1, "Charging");
    lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xd0ff00), LV_PART_MAIN|LV_STATE_DEFAULT);
    
    battery_level_to_int = (int)battery_level;
    lv_label_set_text(guider_ui.screen_label_38, battery_level_to_str);
    lv_label_set_text(guider_ui.screen_label_19, battery_level_to_str);
    
    lv_label_set_text(guider_ui.screen_label_3, totalKWattHr_to_str);
    lv_label_set_text(guider_ui.screen_label_28, totalKWattHr_to_str);
    
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
      lv_label_set_text(guider_ui.screen_label_25, power_str);

    //add estimated end time
    float remaining_charge;
    remaining_charge = max_limit - battery_level;
    int remaining_time_in_seconds;
    remaining_time_in_seconds = remaining_charge * 10;
    char diff_time[20];
    diffTime = secondsToTime(remaining_time_in_seconds);
    snprintf(diff_time, sizeof(diff_time), "00:%02d:%02d", diffTime.minutes, diffTime.seconds);
    lv_label_set_text(guider_ui.screen_label_11, diff_time);
    //add estimated end time
  }else{

    if (set_paused == 1){
      printf("Automatic pause triggered (battery limit reached)\n");
      pause_charging();  // This will now capture pause time inside the function
      printf("\nready to pause: elseIf\n");
      lv_obj_clear_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
      lv_label_set_text(guider_ui.screen_label_11, "00:00:00");
      // Add dial data
        lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, 0);
        lv_label_set_text(guider_ui.screen_label_25, "0");
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
    lv_snprintf(buf, sizeof(buf), "%d%%", (int)lv_slider_get_value(slider));
    max_limit = lv_slider_get_value(slider);
    lv_label_set_text(guider_ui.screen_label_34, buf);
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
            lv_label_set_text(guider_ui.screen_label_10, "--:--:--");
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
            //lv_label_set_text(guider_ui.screen_label_10, "12:12:12");
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
  lv_label_set_text(guider_ui.screen_label_1, "final_energy: Pause");
}

static void screen_img_19_custom_event_custom_handler (lv_event_t *e)
{
  // resume_charging();
  is_new_session = false;
  lv_label_set_text(guider_ui.screen_label_1, "final_energy: Play");
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
