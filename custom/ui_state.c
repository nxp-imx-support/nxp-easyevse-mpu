/*
 * SPDX-License-Identifier: MIT
 * Copyright 2026 NXP
 */

#include "ui_state.h"
#include "gui_guider.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

/* The lv_ui created by GUI Guider — declared in gui_guider.h, defined in main.c. */
extern lv_ui guider_ui;

/* ----------------------------------------------------------------------
 * Internal state struct.
 *
 * All fields are written under ui_mutex by ui_set_* (any thread) and
 * snapshot-then-cleared by the apply timer (LVGL thread).
 * -------------------------------------------------------------------- */
typedef struct {
    /* Status / state label */
    char     state_text[64];
    uint32_t state_color;
    bool     state_dirty;

    /* CSMS connection icon */
    int  csms_state;          /* -1 unknown, 0 down, 1 up */
    bool csms_dirty;

    /* "Waiting for EVerest" overlay */
    bool overlay_visible;
    bool overlay_dirty;

    /* EVSE/EV metadata */
    char evse_id_text[128];
    bool evse_id_dirty;
    char ev_id_text[128];
    bool ev_id_dirty;
    char protocol_text[64];
    bool protocol_dirty;
    char direction_text[32];
    const lv_img_dsc_t *direction_arrow_src;
    bool direction_arrow_visible;
    bool direction_dirty;

    /* Powermeter */
    char meter_id_text[64];
    bool meter_id_dirty;
    char voltage_text[32];
    bool voltage_dirty;
    char current_text[32];
    bool current_dirty;
    char temperature_text[16];
    bool temperature_dirty;
    char connector_text[64];
    bool connector_dirty;

    /* Session timing/energy */
    char start_time_text[32];
    bool start_time_dirty;
    char start_time_summary_text[32];
    bool start_time_summary_dirty;
    char end_time_text[32];
    bool end_time_dirty;
    char energy_text[32];
    bool energy_dirty;
    char energy_summary_text[32];
    bool energy_summary_dirty;
    char duration_text[32];
    bool duration_dirty;
    char duration_summary_text[32];
    bool duration_summary_dirty;
    char eta_text[32];
    bool eta_dirty;

    /* Battery / power gauge */
    float battery_soc;
    bool  battery_dirty;
    float power_kw;
    bool  power_dirty;

    /* NFC / Auth */
    char uid_text[64];
    bool uid_dirty;
    char card_type_text[64];
    bool card_type_dirty;
    char card_status_text[64];
    uint32_t card_status_color;
    bool card_status_dirty;
    char auth_type_text[64];
    bool auth_type_dirty;

    /* Event label */
    char event_text[64];
    bool event_dirty;

    /* Background car image */
    const lv_img_dsc_t *car_image_src;
    bool car_image_dirty;

    /* End-of-session popup: deferred 150 ms after a fresh image swap. */
    bool popup_requested;
    bool popup_hide_requested;
    bool popup_dismissed;          /* user tapped the cross - force-hide, clear all */
    bool popup_dismissed_sticky;   /* sticky: suppress re-show until next session */
    bool popup_discharging;        /* caption: Discharging vs Charging session */

    /* Active-session widget group */
    bool active_session_visible;
    bool active_session_visibility_dirty;

    /* sw_2 checked state */
    bool sw2_checked;
    bool sw2_dirty;
} ui_state_t;

static ui_state_t      g_ui;
static pthread_mutex_t g_ui_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Tick at which the last background-image swap was committed to LVGL.
 * Read/written only on the LVGL thread (no lock needed). */
static uint32_t g_last_image_apply_tick;

/* Tick at which the end-of-session popup (cont_3) became visible. 0 when
 * the popup is hidden. The apply timer refuses to honor a hide-request
 * until POPUP_MIN_VISIBLE_MS have elapsed since this tick, so the user
 * always gets a readable view of the session summary even if a new session
 * (AuthRequired) starts almost immediately. */
static uint32_t g_popup_visible_since;
#define POPUP_MIN_VISIBLE_MS 3000

/* ----------------------------------------------------------------------
 * Apply timer — runs on the LVGL thread every 50 ms. Drains dirty fields.
 *
 * Snapshot-then-apply: we copy g_ui under the lock, clear its dirty flags,
 * then release the lock and call lv_* on our local snapshot. This keeps
 * lock duration to a memcpy and decouples LVGL render time from the
 * network thread.
 * -------------------------------------------------------------------- */
static void clear_dirty_flags_locked(void)
{
    g_ui.state_dirty                       = false;
    g_ui.csms_dirty                        = false;
    g_ui.overlay_dirty                     = false;
    g_ui.evse_id_dirty                     = false;
    g_ui.ev_id_dirty                       = false;
    g_ui.protocol_dirty                    = false;
    g_ui.direction_dirty                   = false;
    g_ui.meter_id_dirty                    = false;
    g_ui.voltage_dirty                     = false;
    g_ui.current_dirty                     = false;
    g_ui.temperature_dirty                 = false;
    g_ui.connector_dirty                   = false;
    g_ui.start_time_dirty                  = false;
    g_ui.start_time_summary_dirty          = false;
    g_ui.end_time_dirty                    = false;
    g_ui.energy_dirty                      = false;
    g_ui.energy_summary_dirty              = false;
    g_ui.duration_dirty                    = false;
    g_ui.duration_summary_dirty            = false;
    g_ui.eta_dirty                         = false;
    g_ui.battery_dirty                     = false;
    g_ui.power_dirty                       = false;
    g_ui.uid_dirty                         = false;
    g_ui.card_type_dirty                   = false;
    g_ui.card_status_dirty                 = false;
    g_ui.auth_type_dirty                   = false;
    g_ui.event_dirty                       = false;
    g_ui.car_image_dirty                   = false;
    g_ui.active_session_visibility_dirty   = false;
    g_ui.sw2_dirty                         = false;
    /* popup_requested / popup_hide_requested are cleared on apply, not here:
     * the popup_requested flag stays set across ticks until the 150 ms image
     * settling delay has elapsed. */
}

/* Persistent buffers backing lv_label_set_text_static (LVGL keeps the pointer,
 * not a copy). One per label so updates never race with the renderer. */
static char buf_state[64];
static char buf_evse_id[128];
static char buf_ev_id[128];
static char buf_protocol[64];
static char buf_direction[32];
static char buf_meter_id[64];
static char buf_voltage[32];
static char buf_current[32];
static char buf_temperature[16];
static char buf_connector[64];
static char buf_start_time_main[32];
static char buf_start_time_summary[32];
static char buf_end_time[32];
static char buf_energy_main[32];
static char buf_energy_summary[32];
static char buf_duration_main[32];
static char buf_duration_summary[32];
static char buf_eta[32];
static char buf_battery[16];
static char buf_power[16];
static char buf_uid[64];
static char buf_card_type[64];
static char buf_card_status[64];
static char buf_auth_type[64];
static char buf_event[64];

static void apply_snapshot(const ui_state_t *s)
{
    if (s->state_dirty) {
        strncpy(buf_state, s->state_text, sizeof(buf_state) - 1);
        buf_state[sizeof(buf_state) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_1, buf_state);
        lv_obj_set_style_text_color(guider_ui.screen_label_1,
                                    lv_color_hex(s->state_color),
                                    LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_invalidate(guider_ui.screen_label_1);
    }

    if (s->csms_dirty) {
        if (s->csms_state == 1) {
            lv_obj_clear_flag(guider_ui.screen_img_11, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(guider_ui.screen_img_16, LV_OBJ_FLAG_HIDDEN);
        } else {
            /* 0, -1, anything else -> show disconnected icon */
            lv_obj_add_flag(guider_ui.screen_img_11, LV_OBJ_FLAG_HIDDEN);
            lv_obj_clear_flag(guider_ui.screen_img_16, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (s->overlay_dirty) {
        if (s->overlay_visible) {
            lv_obj_clear_flag(guider_ui.screen_cont_4, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(guider_ui.screen_cont_4, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (s->evse_id_dirty) {
        strncpy(buf_evse_id, s->evse_id_text, sizeof(buf_evse_id) - 1);
        buf_evse_id[sizeof(buf_evse_id) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_43, buf_evse_id);
    }

    if (s->ev_id_dirty) {
        strncpy(buf_ev_id, s->ev_id_text, sizeof(buf_ev_id) - 1);
        buf_ev_id[sizeof(buf_ev_id) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_44, buf_ev_id);
    }

    if (s->protocol_dirty) {
        strncpy(buf_protocol, s->protocol_text, sizeof(buf_protocol) - 1);
        buf_protocol[sizeof(buf_protocol) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_53, buf_protocol);
    }

    if (s->direction_dirty) {
        strncpy(buf_direction, s->direction_text, sizeof(buf_direction) - 1);
        buf_direction[sizeof(buf_direction) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_55, buf_direction);
        if (s->direction_arrow_src != NULL) {
            lv_img_set_src(guider_ui.screen_img_19, s->direction_arrow_src);
        }
        if (s->direction_arrow_visible) {
            lv_obj_clear_flag(guider_ui.screen_img_19, LV_OBJ_FLAG_HIDDEN);
        } else {
            lv_obj_add_flag(guider_ui.screen_img_19, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (s->meter_id_dirty) {
        strncpy(buf_meter_id, s->meter_id_text, sizeof(buf_meter_id) - 1);
        buf_meter_id[sizeof(buf_meter_id) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_56, buf_meter_id);
    }

    if (s->voltage_dirty) {
        strncpy(buf_voltage, s->voltage_text, sizeof(buf_voltage) - 1);
        buf_voltage[sizeof(buf_voltage) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_54, buf_voltage);
    }

    if (s->current_dirty) {
        strncpy(buf_current, s->current_text, sizeof(buf_current) - 1);
        buf_current[sizeof(buf_current) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_60, buf_current);
    }

    if (s->temperature_dirty) {
        strncpy(buf_temperature, s->temperature_text, sizeof(buf_temperature) - 1);
        buf_temperature[sizeof(buf_temperature) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_4, buf_temperature);
    }

    if (s->connector_dirty) {
        strncpy(buf_connector, s->connector_text, sizeof(buf_connector) - 1);
        buf_connector[sizeof(buf_connector) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_connector, buf_connector);
    }

    if (s->start_time_dirty) {
        strncpy(buf_start_time_main, s->start_time_text, sizeof(buf_start_time_main) - 1);
        buf_start_time_main[sizeof(buf_start_time_main) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_10, buf_start_time_main);
    }

    if (s->start_time_summary_dirty) {
        strncpy(buf_start_time_summary, s->start_time_summary_text, sizeof(buf_start_time_summary) - 1);
        buf_start_time_summary[sizeof(buf_start_time_summary) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_29, buf_start_time_summary);
    }

    if (s->end_time_dirty) {
        strncpy(buf_end_time, s->end_time_text, sizeof(buf_end_time) - 1);
        buf_end_time[sizeof(buf_end_time) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_30, buf_end_time);
    }

    if (s->energy_dirty) {
        strncpy(buf_energy_main, s->energy_text, sizeof(buf_energy_main) - 1);
        buf_energy_main[sizeof(buf_energy_main) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_3, buf_energy_main);
    }

    if (s->energy_summary_dirty) {
        strncpy(buf_energy_summary, s->energy_summary_text, sizeof(buf_energy_summary) - 1);
        buf_energy_summary[sizeof(buf_energy_summary) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_28, buf_energy_summary);
    }

    if (s->duration_dirty) {
        strncpy(buf_duration_main, s->duration_text, sizeof(buf_duration_main) - 1);
        buf_duration_main[sizeof(buf_duration_main) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_11, buf_duration_main);
    }

    if (s->duration_summary_dirty) {
        strncpy(buf_duration_summary, s->duration_summary_text, sizeof(buf_duration_summary) - 1);
        buf_duration_summary[sizeof(buf_duration_summary) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_31, buf_duration_summary);
    }

    if (s->eta_dirty) {
        strncpy(buf_eta, s->eta_text, sizeof(buf_eta) - 1);
        buf_eta[sizeof(buf_eta) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_11, buf_eta);
    }

    if (s->battery_dirty) {
        float soc = s->battery_soc;
        if (soc < 0) soc = 0;
        if (soc > 100) soc = 100;
        snprintf(buf_battery, sizeof(buf_battery), "%.1f", soc);
        lv_label_set_text_static(guider_ui.screen_label_38, buf_battery);
        lv_label_set_text_static(guider_ui.screen_label_19, buf_battery);
        lv_bar_set_value(guider_ui.screen_bar_2, (int)soc, LV_ANIM_OFF);
    }

    if (s->power_dirty) {
        float kw = s->power_kw < 0 ? 0 : s->power_kw;
        snprintf(buf_power, sizeof(buf_power), "%.0f", kw);
        lv_label_set_text_static(guider_ui.screen_label_25, buf_power);
        lv_meter_set_indicator_value(guider_ui.screen_meter_1,
                                     guider_ui.screen_meter_1_scale_0_ndline_0,
                                     (int)kw);
    }

    if (s->uid_dirty) {
        strncpy(buf_uid, s->uid_text, sizeof(buf_uid) - 1);
        buf_uid[sizeof(buf_uid) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_57, buf_uid);
    }

    if (s->card_type_dirty) {
        strncpy(buf_card_type, s->card_type_text, sizeof(buf_card_type) - 1);
        buf_card_type[sizeof(buf_card_type) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_58, buf_card_type);
    }

    if (s->card_status_dirty) {
        strncpy(buf_card_status, s->card_status_text, sizeof(buf_card_status) - 1);
        buf_card_status[sizeof(buf_card_status) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_59, buf_card_status);
        lv_obj_set_style_text_color(guider_ui.screen_label_59,
                                    lv_color_hex(s->card_status_color),
                                    LV_PART_MAIN | LV_STATE_DEFAULT);
    }

    if (s->auth_type_dirty) {
        strncpy(buf_auth_type, s->auth_type_text, sizeof(buf_auth_type) - 1);
        buf_auth_type[sizeof(buf_auth_type) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_62, buf_auth_type);
    }

    if (s->event_dirty) {
        strncpy(buf_event, s->event_text, sizeof(buf_event) - 1);
        buf_event[sizeof(buf_event) - 1] = '\0';
        lv_label_set_text_static(guider_ui.screen_label_63, buf_event);
    }

    if (s->car_image_dirty && s->car_image_src != NULL) {
        lv_img_set_src(guider_ui.screen_img_2, s->car_image_src);
        g_last_image_apply_tick = lv_tick_get();
    }

    if (s->active_session_visibility_dirty) {
        if (s->active_session_visible) {
            lv_obj_clear_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
            lv_obj_clear_flag(guider_ui.screen_bar_2,    LV_OBJ_FLAG_HIDDEN);
            lv_obj_clear_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
            lv_obj_clear_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
            /* img_19 (direction arrow) is managed by direction_dirty */
        } else {
            lv_obj_add_flag(guider_ui.screen_label_40, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(guider_ui.screen_bar_2,    LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(guider_ui.screen_img_19,   LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(guider_ui.screen_label_19, LV_OBJ_FLAG_HIDDEN);
            lv_obj_add_flag(guider_ui.screen_label_38, LV_OBJ_FLAG_HIDDEN);
        }
    }

    if (s->sw2_dirty) {
        if (s->sw2_checked) {
            lv_obj_add_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
        } else {
            lv_obj_clear_state(guider_ui.screen_sw_2, LV_STATE_CHECKED);
        }
    }
}

static void ui_apply_timer_cb(lv_timer_t *timer)
{
    (void)timer;

    ui_state_t snap;

    pthread_mutex_lock(&g_ui_mutex);
    snap = g_ui;                            /* struct copy ~1 KB */
    clear_dirty_flags_locked();
    /* popup_requested / popup_hide_requested are read into snap;
     * we decide below whether to clear them based on the image-settling delay. */
    pthread_mutex_unlock(&g_ui_mutex);

    apply_snapshot(&snap);

    /* End-of-session popup arbitration.
     *
     * Dismiss (user tapped the cross) takes absolute priority: hide now and
     * clear every popup flag + the visibility tracker, so nothing re-shows it.
     *
     * Otherwise: show first (a requested popup always gets one chance to
     * appear), then hide, gated by POPUP_MIN_VISIBLE_MS once visible.
     */

    if (snap.popup_dismissed) {
        lv_obj_add_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
        g_popup_visible_since = 0;
        pthread_mutex_lock(&g_ui_mutex);
        g_ui.popup_dismissed = false;
        g_ui.popup_requested = false;
        g_ui.popup_hide_requested = false;
        pthread_mutex_unlock(&g_ui_mutex);
        return;
    }

    /* Step 1: try to show, if not currently visible and defer-window passed. */
    if (snap.popup_requested && g_popup_visible_since == 0) {
        uint32_t elapsed = lv_tick_get() - g_last_image_apply_tick;
        if (elapsed >= 150) {
            /* Swap the summary caption to match charge/discharge direction.
             * The value fields (energy/start/end/duration) are separate
             * labels, so the line layout is identical between variants. */
            lv_label_set_text_static(
                guider_ui.screen_label_14,
                snap.popup_discharging
                    ? "\n\nDischarging Session Completed!\n\nUsed Energy: \nStart Time: \nEnd Time: \nDischarge Time: "
                    : "\n\nCharging Session Completed!\n\nUsed Energy: \nStart Time: \nEnd Time: \nCharge Time: ");
            lv_obj_clear_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
            g_popup_visible_since = lv_tick_get();
            if (g_popup_visible_since == 0) {
                g_popup_visible_since = 1;  /* reserve 0 = "not visible" */
            }
            pthread_mutex_lock(&g_ui_mutex);
            g_ui.popup_requested = false;
            pthread_mutex_unlock(&g_ui_mutex);
        }
        /* else: still inside the 150 ms image-settle window; retry next tick. */
    }

    /* Step 2: honor hide, but only if popup has been visible long enough. */
    if (snap.popup_hide_requested) {
        bool can_hide = false;
        if (g_popup_visible_since != 0) {
            uint32_t visible_for = lv_tick_get() - g_popup_visible_since;
            can_hide = (visible_for >= POPUP_MIN_VISIBLE_MS);
        } else if (!snap.popup_requested) {
            /* Popup was never shown and no show pending: consume the hide. */
            can_hide = true;
        }
        if (can_hide) {
            lv_obj_add_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
            g_popup_visible_since = 0;
            pthread_mutex_lock(&g_ui_mutex);
            g_ui.popup_hide_requested = false;
            pthread_mutex_unlock(&g_ui_mutex);
        }
        /* else: leave popup_hide_requested set; reconsidered next tick. */
    }
}

/* ----------------------------------------------------------------------
 * Setters - all callable from any thread.
 * -------------------------------------------------------------------- */
#define SAFE_STRCPY(dst, src) do {                              \
        if ((src) != NULL) {                                    \
            strncpy((dst), (src), sizeof(dst) - 1);             \
            (dst)[sizeof(dst) - 1] = '\0';                      \
        } else {                                                \
            (dst)[0] = '\0';                                    \
        }                                                       \
    } while (0)

void ui_set_state(const char *text, uint32_t color)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.state_text, text);
    g_ui.state_color = color;
    g_ui.state_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_csms_connected(int tri_state)
{
    pthread_mutex_lock(&g_ui_mutex);
    g_ui.csms_state = tri_state;
    g_ui.csms_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_overlay_visible(bool visible)
{
    pthread_mutex_lock(&g_ui_mutex);
    g_ui.overlay_visible = visible;
    g_ui.overlay_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_evse_id(const char *formatted)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.evse_id_text, formatted);
    g_ui.evse_id_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_ev_id(const char *formatted)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.ev_id_text, formatted);
    g_ui.ev_id_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_protocol(const char *formatted)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.protocol_text, formatted);
    g_ui.protocol_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_direction(const char *formatted,
                      const lv_img_dsc_t *arrow_src,
                      bool arrow_visible)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.direction_text, formatted);
    g_ui.direction_arrow_src = arrow_src;
    g_ui.direction_arrow_visible = arrow_visible;
    g_ui.direction_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_meter_id(const char *formatted)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.meter_id_text, formatted);
    g_ui.meter_id_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_voltage(float volts)
{
    pthread_mutex_lock(&g_ui_mutex);
    snprintf(g_ui.voltage_text, sizeof(g_ui.voltage_text), "Voltage: %.1f V", volts);
    g_ui.voltage_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_current(float amps)
{
    pthread_mutex_lock(&g_ui_mutex);
    snprintf(g_ui.current_text, sizeof(g_ui.current_text), "%.1f A", amps);
    g_ui.current_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_temperature(float celsius)
{
    pthread_mutex_lock(&g_ui_mutex);
    snprintf(g_ui.temperature_text, sizeof(g_ui.temperature_text), "%.0f", celsius);
    g_ui.temperature_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_connector(const char *formatted)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.connector_text, formatted);
    g_ui.connector_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_start_time(const char *text)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.start_time_text, text);
    g_ui.start_time_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_start_time_summary(const char *text)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.start_time_summary_text, text);
    g_ui.start_time_summary_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_end_time(const char *text)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.end_time_text, text);
    g_ui.end_time_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_energy(const char *text)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.energy_text, text);
    g_ui.energy_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_energy_summary(const char *text)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.energy_summary_text, text);
    g_ui.energy_summary_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_duration(const char *text)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.duration_text, text);
    g_ui.duration_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_duration_summary(const char *text)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.duration_summary_text, text);
    g_ui.duration_summary_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_eta(const char *text)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.eta_text, text);
    g_ui.eta_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_battery_soc(float soc)
{
    pthread_mutex_lock(&g_ui_mutex);
    g_ui.battery_soc = soc;
    g_ui.battery_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_power_kw(float kw)
{
    pthread_mutex_lock(&g_ui_mutex);
    g_ui.power_kw = kw;
    g_ui.power_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_uid(const char *formatted)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.uid_text, formatted);
    g_ui.uid_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_card_type(const char *formatted)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.card_type_text, formatted);
    g_ui.card_type_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_card_status(const char *formatted, uint32_t color)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.card_status_text, formatted);
    g_ui.card_status_color = color;
    g_ui.card_status_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_auth_type(const char *formatted)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.auth_type_text, formatted);
    g_ui.auth_type_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_event(const char *text)
{
    pthread_mutex_lock(&g_ui_mutex);
    SAFE_STRCPY(g_ui.event_text, text);
    g_ui.event_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_car_image(const lv_img_dsc_t *src)
{
    pthread_mutex_lock(&g_ui_mutex);
    g_ui.car_image_src = src;
    g_ui.car_image_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_request_popup(bool discharging)
{
    pthread_mutex_lock(&g_ui_mutex);
    if (!g_ui.popup_dismissed_sticky) {
        /* Sticky-dismissed: the user has already closed this session's popup.
         * Ignore repeated session-end events that would otherwise re-show it.
         * The next session arms ui_arm_popup() to clear the sticky flag. */
        g_ui.popup_requested = true;
        g_ui.popup_discharging = discharging;
    }
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_hide_popup(void)
{
    pthread_mutex_lock(&g_ui_mutex);
    g_ui.popup_hide_requested = true;
    /* Do NOT clear popup_requested here. If a show request is still in
     * flight (waiting for the 150 ms image-settle defer), the user has
     * never actually seen the popup yet — cancelling now would mean the
     * end-of-session summary just vanishes. The apply timer will show
     * the popup first, hold it for POPUP_MIN_VISIBLE_MS, then honor the
     * hide. */
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_dismiss_popup(void)
{
    /* User explicitly tapped the cross. This is a hard close: cancel any
     * pending/latched show request, cancel any deferred hide, and signal the
     * apply timer to hide cont_3 and reset its visibility tracker. Also set
     * the sticky flag so repeated session-end events don't re-show the
     * popup later — only ui_arm_popup() (called on the next session start)
     * clears it. */
    pthread_mutex_lock(&g_ui_mutex);
    g_ui.popup_dismissed = true;
    g_ui.popup_dismissed_sticky = true;
    g_ui.popup_requested = false;
    g_ui.popup_hide_requested = false;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_arm_popup(void)
{
    /* Re-arm the popup for the next session. Call this on session start
     * events (SessionStarted / AuthRequired). Clears the sticky dismiss
     * flag so the end-of-session popup is allowed to appear again. */
    pthread_mutex_lock(&g_ui_mutex);
    g_ui.popup_dismissed_sticky = false;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_active_session_visible(bool visible)
{
    pthread_mutex_lock(&g_ui_mutex);
    g_ui.active_session_visible = visible;
    g_ui.active_session_visibility_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_set_sw2_checked(bool checked)
{
    pthread_mutex_lock(&g_ui_mutex);
    g_ui.sw2_checked = checked;
    g_ui.sw2_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);
}

void ui_session_reset(void)
{
    pthread_mutex_lock(&g_ui_mutex);

    SAFE_STRCPY(g_ui.state_text, "Unplugged");
    g_ui.state_color = 0xdcd1e5;
    g_ui.state_dirty = true;

    SAFE_STRCPY(g_ui.uid_text,           "UID: NA");        g_ui.uid_dirty = true;
    SAFE_STRCPY(g_ui.card_type_text,     "Type: NA");       g_ui.card_type_dirty = true;
    SAFE_STRCPY(g_ui.card_status_text,   "Status: NA");
    g_ui.card_status_color = 0xDCD1E5;                       g_ui.card_status_dirty = true;
    SAFE_STRCPY(g_ui.auth_type_text,     "Auth: NA");       g_ui.auth_type_dirty = true;
    SAFE_STRCPY(g_ui.direction_text,     "Direction: NA");
    g_ui.direction_arrow_src = NULL;
    g_ui.direction_arrow_visible = false;                    g_ui.direction_dirty = true;
    SAFE_STRCPY(g_ui.ev_id_text,         "EV ID: NA");      g_ui.ev_id_dirty = true;
    SAFE_STRCPY(g_ui.protocol_text,      "Protocol: NA");   g_ui.protocol_dirty = true;
    SAFE_STRCPY(g_ui.start_time_text,    "--:--:--");       g_ui.start_time_dirty = true;
    SAFE_STRCPY(g_ui.duration_text,      "--:--:--");       g_ui.duration_dirty = true;
    SAFE_STRCPY(g_ui.energy_text,        "0.000 kWh");      g_ui.energy_dirty = true;

    g_ui.battery_soc = 0.0f;                                 g_ui.battery_dirty = true;
    g_ui.power_kw    = 0.0f;                                 g_ui.power_dirty   = true;

    g_ui.active_session_visible = false;
    g_ui.active_session_visibility_dirty = true;

    g_ui.sw2_checked = true;
    g_ui.sw2_dirty = true;

    pthread_mutex_unlock(&g_ui_mutex);
}

/* ----------------------------------------------------------------------
 * Init
 * -------------------------------------------------------------------- */
void ui_state_init(void)
{
    /* Seed defaults so the first apply tick paints sane "NA" everywhere. */
    pthread_mutex_lock(&g_ui_mutex);
    memset(&g_ui, 0, sizeof(g_ui));

    SAFE_STRCPY(g_ui.state_text,         "Initializing...");
    g_ui.state_color = 0xdcd1e5;                              g_ui.state_dirty = true;
    SAFE_STRCPY(g_ui.evse_id_text,       "EVSE ID: NA");      g_ui.evse_id_dirty = true;
    SAFE_STRCPY(g_ui.ev_id_text,         "EV ID: NA");        g_ui.ev_id_dirty = true;
    SAFE_STRCPY(g_ui.protocol_text,      "Protocol: NA");     g_ui.protocol_dirty = true;
    SAFE_STRCPY(g_ui.direction_text,     "Direction: NA");    g_ui.direction_dirty = true;
    SAFE_STRCPY(g_ui.meter_id_text,      "Meter: NA");        g_ui.meter_id_dirty = true;
    SAFE_STRCPY(g_ui.voltage_text,       "Voltage: NA");      g_ui.voltage_dirty = true;
    SAFE_STRCPY(g_ui.current_text,       "0.0 A");            g_ui.current_dirty = true;
    SAFE_STRCPY(g_ui.connector_text,     "Connector: NA");    g_ui.connector_dirty = true;
    SAFE_STRCPY(g_ui.uid_text,           "UID: NA");          g_ui.uid_dirty = true;
    SAFE_STRCPY(g_ui.card_type_text,     "Type: NA");         g_ui.card_type_dirty = true;
    SAFE_STRCPY(g_ui.card_status_text,   "Status: NA");
    g_ui.card_status_color = 0xDCD1E5;                        g_ui.card_status_dirty = true;
    SAFE_STRCPY(g_ui.auth_type_text,     "Auth: NA");         g_ui.auth_type_dirty = true;
    SAFE_STRCPY(g_ui.event_text,         "Enabled");          g_ui.event_dirty = true;
    pthread_mutex_unlock(&g_ui_mutex);

    /* 50 ms cadence: ~20 Hz, comfortably faster than human perception. */
    lv_timer_create(ui_apply_timer_cb, 50, NULL);
}
