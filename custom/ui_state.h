/*
 * SPDX-License-Identifier: MIT
 * Copyright 2026 NXP
 *
 * ui_state - thread-safe latest-state buffer between MQTT (Paho network
 * thread) and the LVGL main thread.
 *
 */

#ifndef UI_STATE_H
#define UI_STATE_H

#include <stdbool.h>
#include <stdint.h>
#include "lvgl.h"

/* Create the apply timer (50 ms) and seed initial widget values. */
void ui_state_init(void);

/* ===== Status / connection ============================================ */
void ui_set_state(const char *text, uint32_t color);
void ui_set_csms_connected(int tri_state);
void ui_set_overlay_visible(bool visible);

/* ===== EVSE / EV metadata ============================================= */
void ui_set_evse_id(const char *formatted);
void ui_set_ev_id(const char *formatted);
void ui_set_protocol(const char *formatted);
void ui_set_direction(const char *formatted,
                      const lv_img_dsc_t *arrow_src,
                      bool arrow_visible);

/* ===== Powermeter ===================================================== */
void ui_set_meter_id(const char *formatted);
void ui_set_voltage(float volts);
void ui_set_current(float amps);
void ui_set_temperature(float celsius);
void ui_set_connector(const char *formatted);

/* ===== Session timing / energy ======================================== */
void ui_set_start_time(const char *text);
void ui_set_start_time_summary(const char *text);
void ui_set_end_time(const char *text);
void ui_set_energy(const char *text);
void ui_set_energy_summary(const char *text);
void ui_set_duration(const char *text);
void ui_set_duration_summary(const char *text);
void ui_set_eta(const char *text);

/* ===== Battery / power gauges ========================================= */
void ui_set_battery_soc(float soc);
void ui_set_power_kw(float kw);

/* ===== ISO 15118-20 SoC progress bar =================================  */
void ui_set_soc_bar(float present_soc, float target_soc);
void ui_clear_soc_bar(void);

/* ===== NFC / Auth ===================================================== */
void ui_set_uid(const char *formatted);
void ui_set_card_type(const char *formatted);
void ui_set_card_status(const char *formatted, uint32_t color);
void ui_set_auth_type(const char *formatted);

/* ===== Event / image / popup ========================================== */
void ui_set_event(const char *text);
void ui_set_car_image(const lv_img_dsc_t *src);
void ui_request_popup(bool discharging);
void ui_hide_popup(void);
void ui_dismiss_popup(void);
void ui_arm_popup(void);

/* ===== Misc ============================================================ */
/* Bulk reset applied when a session ends */
void ui_session_reset(void);

/* Show/hide the active-session widget group  */
void ui_set_active_session_visible(bool visible);

/* sw_2 checked state. */
void ui_set_sw2_checked(bool checked);

#endif /* UI_STATE_H */
