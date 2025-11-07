/*
* Copyright 2023 NXP
* NXP Confidential and Proprietary. This software is owned or controlled by NXP and may only be used strictly in
* accordance with the applicable license terms. By expressly accepting such terms or by downloading, installing,
* activating and/or otherwise using the software, you are agreeing that you have read, and that you agree to
* comply with and are bound by, such license terms.  If you do not agree to be bound by the applicable license
* terms, then you may not retain, install, activate or otherwise use the software.
*/

#ifndef __CUSTOM_H_
#define __CUSTOM_H_
#ifdef __cplusplus
extern "C" {
#endif

#include "gui_guider.h"
#include "MQTTClient.h"

void custom_init(lv_ui *ui);
static void screen_sw_1_event_custom_handler (lv_event_t *e);
static void screen_slider_1_event_custom_handler (lv_event_t *e);
static void screen_slider_2_event_custom_handler (lv_event_t *e);
static void screen_sw_2_custom_event_custom_handler (lv_event_t *e);
static void screen_img_18_custom_event_custom_handler (lv_event_t *e);
static void screen_img_19_custom_event_custom_handler (lv_event_t *e);
void get_mqtt_state_for_evse();
int messageArrived(void *context, char *topic, int topicLen, MQTTClient_message *message);
void set_max_temp();
void plug_in();
void unplug();
void pause_charging();
void resume_charging();
void max_current(int max_current);
void set_screen_digital_clock_1();
void get_current_time();
void update_time();
void increase_battery_level();


#ifdef __cplusplus
}
#endif
#endif /* EVENT_CB_H_ */
