/*
* Copyright 2023-2025 NXP
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
char final_energy[20];
char hour[10];
char minutes[10];
char seconds[10];
char am_pm[10];
static time_t last_update_time = 0;
static const int UPDATE_INTERVAL_SECONDS = 1;
bool is_new_session=false;
bool is_session_started=false;
float battery_level = 20.0f;
bool active_session=false;
int max_limit=25;
float totalKWattHr = 0.000f;
int set_paused=0;


// Time calculation code end


// Structure to represent time
typedef struct {
    int hours;
    int minutes;
    int seconds;
    char ampm; // 'A' for AM, 'P' for PM
} Time;

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

void custom_init(lv_ui *ui)
{
    /* Add your codes here */
  get_mqtt_state_for_evse();
  set_screen_digital_clock_1();

  lv_timer_t * clock_timer = lv_timer_create(clock_update_timer_cb, 100, NULL);

  // setenv("LD_LIBRARY_PATH","/usr/local/lib64",1);
  const char *location = getenv("LOCATION");
  if (location != NULL){
    printf("PATH: %s", location);
    lv_label_set_text(guider_ui.screen_label_7, (char *)location);
  }else{
    lv_label_set_text(guider_ui.screen_label_7, "NXP Plot 1");
  }     
    
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
  
  printf("DEBUG: hour_24 = %d\n", hour_24);
  printf("DEBUG: am_pm string = '%s'\n", am_pm);
  printf("DEBUG: am_pm[0] = '%c', am_pm[1] = '%c'\n", am_pm[0], am_pm[1]);
  
  // Convert to 12-hour format
  int hour_12 = hour_24 % 12;
  if (hour_12 == 0) hour_12 = 12; // Handle midnight and noon
  
  sprintf(hour, "%02d", hour_12);
  sprintf(minutes, "%02d", timeinfo->tm_min);
  sprintf(seconds, "%02d", timeinfo->tm_sec);
  
  printf("Current local time and date: %s", asctime(timeinfo));
  printf("Time: %s:%s:%s %s (24h: %d)\n", hour, minutes, seconds, am_pm, hour_24);
}


void set_screen_digital_clock_1(){
  update_time();
  screen_digital_clock_1_hour_value = atoi(hour);
  screen_digital_clock_1_min_value = atoi(minutes);
  screen_digital_clock_1_sec_value = atoi(seconds);
  strcpy(screen_digital_clock_1_meridiem, am_pm);
}

int messageArrived(void *context, char *topic, int topicLen, MQTTClient_message *message) {
    printf("Received: %s -> %.*s\n", topic, message->payloadlen, (char *)message->payload);
    if (strcmp(topic,"everest_external/nodered/1/state/state_string") == 0){
       lv_label_set_text(guider_ui.screen_label_1, (char *)message->payload);
       lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xdcd1e5), LV_PART_MAIN|LV_STATE_DEFAULT);
       lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_arial_30, 0);
      if (
          strcmp((char *)message->payload, "StoppingCharging") == 0 ||
          strcmp((char *)message->payload, "Finished") == 0 ||
          strcmp((char *)message->payload, "Idle") == 0
      ) {
          active_session = false;
          lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xdcd1e5), LV_PART_MAIN|LV_STATE_DEFAULT);
          lv_img_set_src(guider_ui.screen_img_2, &_Car_Unplugged_0_alpha_1280x800);
          
          // migrated_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_
          lv_label_set_text(guider_ui.screen_label_10, "--:--:--");
          lv_label_set_text(guider_ui.screen_label_1, "Unplugged");
          lv_obj_add_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
          char string_time_out[20];
          char diff_time[20];
  
          set_screen_digital_clock_1();
          endTime.hours = atoi(hour);
          endTime.minutes = atoi(minutes);
          endTime.seconds = atoi(seconds); 
          endTime.ampm = strcmp(am_pm,"AM") ? 'A' : 'p';
  
          startTimeInSeconds = timeToSeconds(startTime);
          endTimeInSeconds = timeToSeconds(endTime);
  
          diffInSeconds = endTimeInSeconds - startTimeInSeconds;
          if (diffInSeconds < 0){
            diffInSeconds +=86400;
          }
          diffTime = secondsToTime(diffInSeconds);
  
          if (diffTime.hours == 12){
            diffTime.hours = 00;
          }
          
          snprintf(string_time_out, sizeof(string_time_out), "%s:%s:%s %s", hour, minutes, seconds, am_pm);
          snprintf(diff_time, sizeof(diff_time), "%02d:%02d:%02d", diffTime.hours, diffTime.minutes, diffTime.seconds);
          lv_label_set_text(guider_ui.screen_label_30, string_time_out);
          lv_label_set_text(guider_ui.screen_label_31, diff_time);
          if (is_session_started){
            lv_obj_clear_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
            battery_level = 20.0;
            totalKWattHr = 0.000;
            lv_label_set_text(guider_ui.screen_label_38, "20.0");
            lv_label_set_text(guider_ui.screen_label_19, "20.0");
            lv_label_set_text(guider_ui.screen_label_3, "0.0kWh");
            lv_label_set_text(guider_ui.screen_label_11, "--:--:--");
            // Add dial data
              lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, 0);
              lv_label_set_text(guider_ui.screen_label_25, "0");
            // Add dial data
            // lv_label_set_text(guider_ui.screen_label_28, "0.0kWh");
            lv_bar_set_value(guider_ui.screen_bar_2, 20, LV_ANIM_OFF);
            is_session_started = false;
          }
        // migrated_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_+_
      }
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
          lv_label_set_text(guider_ui.screen_label_1, "Authenticating...");
          is_new_session = true;	
      }

      if (
          strcmp((char *)message->payload, "Charging") == 0
      ) {
          active_session = true;
          lv_img_set_src(guider_ui.screen_img_2, &_Car_plugged_alpha_1280x800);
          lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xd0ff00), LV_PART_MAIN|LV_STATE_DEFAULT);
      }      
      
      if ((strcmp((char *)message->payload,"PrepareCharging") == 0) && (is_new_session)){
        lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_arial_30, 0);
        lv_label_set_text(guider_ui.screen_label_1, "Authenticating...");
        char string_time[20];
        set_screen_digital_clock_1();
        is_session_started = true;
        active_session = false;
          
        startTime.hours = atoi(hour);
        startTime.minutes = atoi(minutes);
        startTime.seconds = atoi(seconds); 
        startTime.ampm = strcmp(am_pm,"AM") ? 'A' : 'p';
        
        snprintf(string_time, sizeof(string_time), "%s:%s:%s %s", hour, minutes, seconds, am_pm);
        sleep(2);
        lv_label_set_text(guider_ui.screen_label_10, string_time);
        
        // lv_obj_clear_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
        // lv_obj_clear_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
        // lv_obj_clear_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
        // lv_obj_clear_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
		lv_obj_clear_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
		lv_obj_clear_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
		lv_obj_clear_flag(guider_ui.screen_bar_2, LV_OBJ_FLAG_HIDDEN);
        
        lv_label_set_text(guider_ui.screen_label_29, string_time);
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
      //move to increare_batery_level lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, atoi(message->payload));
      // lv_label_set_text_fmt(gui->speed_label_digit, "%"LV_PRId32, speed);
      //move to increare_batery_level lv_label_set_text(guider_ui.screen_label_25, (char *)message->payload);

       int result = system("ping -c 1 8.8.8.8 -W 2 2>/dev/null 1>/dev/null");

      if (result == 0) {
          printf("Internet connection is available.\n");
          lv_obj_add_flag(guider_ui.screen_label_13, LV_OBJ_FLAG_HIDDEN);
          // lv_obj_add_flag(guider_ui.screen_label_15, LV_OBJ_FLAG_HIDDEN);
          lv_obj_clear_flag(guider_ui.screen_img_6, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_img_17, LV_OBJ_FLAG_HIDDEN);
        
      } else {
          lv_obj_clear_flag(guider_ui.screen_label_13, LV_OBJ_FLAG_HIDDEN);
          // lv_obj_clear_flag(guider_ui.screen_label_15, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_img_6, LV_OBJ_FLAG_HIDDEN);
          lv_obj_clear_flag(guider_ui.screen_img_17, LV_OBJ_FLAG_HIDDEN);
          printf("Internet connection is not available.\n");
      } 
      increase_battery_level();

    }else if (strcmp(topic,"everest_api/ocpp/csms_status") == 0){
      printf("Received topic: %s, value: %.*s\n", topic, message->payloadlen, (char *)message->payload);
      // Toggle images based on status
      if (strcmp((char *)message->payload, "true") == 0 || strcmp((char *)message->payload, "connected") == 0) {
          // Show img_11, hide img_16
          lv_obj_clear_flag(guider_ui.screen_img_11, LV_OBJ_FLAG_HIDDEN);
          lv_obj_add_flag(guider_ui.screen_img_16, LV_OBJ_FLAG_HIDDEN);
      } else if (strcmp((char *)message->payload, "false") == 0 || strcmp((char *)message->payload, "disconnected") == 0) {
          // Hide img_11, show img_16
          lv_obj_add_flag(guider_ui.screen_img_11, LV_OBJ_FLAG_HIDDEN);
          lv_obj_clear_flag(guider_ui.screen_img_16, LV_OBJ_FLAG_HIDDEN);
      } else {
          // Default: hide both or show img_16
          lv_obj_add_flag(guider_ui.screen_img_11, LV_OBJ_FLAG_HIDDEN);
          lv_obj_clear_flag(guider_ui.screen_img_16, LV_OBJ_FLAG_HIDDEN);
      }
        
     } else if (strcmp(topic,"everest_external/nodered/1/powermeter/totalKWattHr") == 0){
      // will uncomment with actual values
      // lv_label_set_text(guider_ui.screen_label_3, (char *)message->payload);
      // strcpy(final_energy,(char *)message->payload);
      printf("this is blank");
      // will uncomment with actual values
      
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
  /* Introduced delay to avoid subscription lost
     due to Timing/race conditoin issue
   */
  usleep(100000); // 100ms delay
  rc = MQTTClient_subscribe(client, "everest_external/nodered/1/powermeter/totalKWattHr", QOS);
  printf("Subscribe totalKWattHr: %d\n", rc);
  usleep(100000); // 100ms delay
  rc = MQTTClient_subscribe(client, "everest_external/nodered/1/powermeter/totalKw", QOS);
  printf("Subscribe totalKw: %d\n", rc);
  usleep(100000); // 100ms delay
  rc = MQTTClient_subscribe(client, "everest_external/nodered/1/state/temperature", QOS);
  printf("Subscribe temperature: %d\n", rc);
  usleep(100000); // 100ms delay
  rc = MQTTClient_subscribe(client, "everest_external/nodered/1/state/state_string", QOS);
  printf("Subscribe state_string: %d\n", rc);
  usleep(100000); // 100ms delay
  rc = MQTTClient_subscribe(client, "everest_api/ocpp/csms_status", QOS);
  printf("Subscribe csms_status: %d\n", rc);

  // MQTTClient_subscribe(client, "everest_external/nodered/1/cmd/set_max_current", QOS); 

  // MQTTClient_message pubmsg = MQTTClient_message_initializer; 
  // set_max_temp();
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

void pause_charging(){
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

  // if (battery_level > max_limit){
  //   printf("battery level match");
  //   pause_charging();
  // }
  
  if (active_session && (battery_level < max_limit)){
    // printf("battery level not match: If");
    set_paused = 1;
    battery_level += 0.1;
    totalKWattHr += 0.0050;
    sprintf(battery_level_to_str, "%.1f", battery_level);
    
    sprintf(totalKWattHr_to_str, "%.3f kWh", totalKWattHr);
    
    lv_label_set_text(guider_ui.screen_label_1, "Charging");
    lv_obj_set_style_text_color(guider_ui.screen_label_1, lv_color_hex(0xd0ff00), LV_PART_MAIN|LV_STATE_DEFAULT);
    
    battery_level_to_int = (int)battery_level;
    lv_label_set_text(guider_ui.screen_label_38, battery_level_to_str);
    lv_label_set_text(guider_ui.screen_label_19, battery_level_to_str);
    
    lv_label_set_text(guider_ui.screen_label_3, totalKWattHr_to_str);
    lv_label_set_text(guider_ui.screen_label_28, totalKWattHr_to_str);
    
    lv_bar_set_value(guider_ui.screen_bar_2, battery_level_to_int, LV_ANIM_OFF);

    // Add dial data
      lv_meter_set_indicator_value(guider_ui.screen_meter_1, guider_ui.screen_meter_1_scale_0_ndline_0, 8);
      // lv_label_set_text_fmt(gui->speed_label_digit, "%"LV_PRId32, speed);
      lv_label_set_text(guider_ui.screen_label_25, "8");
    // Add dial data
    
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
    // printf("If bat state: %d",set_paused);
  }else{
    // printf("\nbattery level matched\n");
    // printf("else bat state: %d",set_paused);
    if (set_paused == 1){
      pause_charging();
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
    lv_snprintf(buf, sizeof(buf), "%d% %", (char)lv_slider_get_value(slider));
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
