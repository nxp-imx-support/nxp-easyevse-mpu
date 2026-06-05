/*
* Copyright 2026 NXP
* NXP Confidential and Proprietary. This software is owned or controlled by NXP and may only be used strictly in
* accordance with the applicable license terms. By expressly accepting such terms or by downloading, installing,
* activating and/or otherwise using the software, you are agreeing that you have read, and that you agree to
* comply with and are bound by, such license terms.  If you do not agree to be bound by the applicable license
* terms, then you may not retain, install, activate or otherwise use the software.
*/

#ifndef GUI_GUIDER_H
#define GUI_GUIDER_H
#ifdef __cplusplus
extern "C" {
#endif

#include "lvgl.h"

typedef struct
{
  
	lv_obj_t *screen;
	bool screen_del;
	lv_obj_t *screen_cont_1;
	lv_obj_t *screen_img_2;
	lv_obj_t *screen_label_1;
	lv_obj_t *screen_label_3;
	lv_obj_t *screen_img_4;
	lv_obj_t *screen_img_5;
	lv_obj_t *screen_slider_1;
	lv_obj_t *screen_label_6;
	lv_obj_t *screen_btn_1;
	lv_obj_t *screen_btn_1_label;
	lv_obj_t *screen_btn_2;
	lv_obj_t *screen_btn_2_label;
	lv_obj_t *screen_img_6;
	lv_obj_t *screen_digital_clock_1;
	lv_obj_t *screen_label_7;
	lv_obj_t *screen_label_8;
	lv_obj_t *screen_img_7;
	lv_obj_t *screen_label_9;
	lv_obj_t *screen_label_12;
	lv_obj_t *screen_label_11;
	lv_obj_t *screen_img_11;
	lv_obj_t *screen_bar_1;
	lv_obj_t *screen_sw_2;
	lv_obj_t *screen_label_18;
	lv_obj_t *screen_label_25;
	lv_obj_t *screen_label_26;
	lv_obj_t *screen_label_27;
	lv_obj_t *screen_label_10;
	lv_obj_t *screen_sw_1;
	lv_obj_t *screen_meter_1;
	lv_meter_indicator_t *screen_meter_1_scale_0_ndline_0;
	lv_obj_t *screen_label_4;
	lv_obj_t *screen_img_14;
	lv_obj_t *screen_img_15;
	lv_obj_t *screen_temp_container;
	lv_obj_t *screen_label_deg;
	lv_obj_t *screen_label_c;
	lv_obj_t *screen_label_33;
	lv_obj_t *screen_slider_2;
	lv_obj_t *screen_label_34;
	lv_obj_t *screen_img_16;
	lv_obj_t *screen_bar_2;
	lv_obj_t *screen_img_17;
	lv_obj_t *screen_label_35;
	lv_obj_t *screen_label_38;
	lv_obj_t *screen_label_39;
	lv_obj_t *screen_label_19;
	lv_obj_t *screen_label_40;
	lv_obj_t *screen_img_18;
	lv_obj_t *screen_label_41;
	lv_obj_t *screen_label_42;
	lv_obj_t *screen_label_43;
	lv_obj_t *screen_label_44;
	lv_obj_t *screen_label_45;
	lv_obj_t *screen_label_52;
	lv_obj_t *screen_label_53;
	lv_obj_t *screen_label_54;
	lv_obj_t *screen_label_55;
	lv_obj_t *screen_label_56;
	lv_obj_t *screen_label_connector;
	lv_obj_t *screen_label_57;
	lv_obj_t *screen_label_58;
	lv_obj_t *screen_label_59;
	lv_obj_t *screen_label_60;
	lv_obj_t *screen_label_61;
	lv_obj_t *screen_img_19;
	lv_obj_t *screen_label_62;
	lv_obj_t *screen_label_63;
	lv_obj_t *screen_label_pause_resume;
	lv_obj_t *screen_cont_3;
	lv_obj_t *screen_label_14;
	lv_obj_t *screen_img_9;
	lv_obj_t *screen_label_28;
	lv_obj_t *screen_label_29;
	lv_obj_t *screen_label_30;
	lv_obj_t *screen_label_31;
	lv_obj_t *screen_label_13;
	lv_obj_t *screen_cont_4;
	lv_obj_t *screen_label_50;
	/* SoC progress bar group */
	lv_obj_t *screen_cont_soc;
	lv_obj_t *screen_bar_soc;
	lv_obj_t *screen_label_soc_current;
	lv_obj_t *screen_label_soc_target;
	lv_obj_t *screen_tick_soc_target;
}lv_ui;

typedef void (*ui_setup_scr_t)(lv_ui * ui);

void ui_init_style(lv_style_t * style);

void ui_load_scr_animation(lv_ui *ui, lv_obj_t ** new_scr, bool new_scr_del, bool * old_scr_del, ui_setup_scr_t setup_scr,
                           lv_scr_load_anim_t anim_type, uint32_t time, uint32_t delay, bool is_clean, bool auto_del);

void ui_move_animation(void * var, int32_t duration, int32_t delay, int32_t x_end, int32_t y_end, lv_anim_path_cb_t path_cb,
                       uint16_t repeat_cnt, uint32_t repeat_delay, uint32_t playback_time, uint32_t playback_delay,
                       lv_anim_start_cb_t start_cb, lv_anim_ready_cb_t ready_cb, lv_anim_deleted_cb_t deleted_cb);

void ui_scale_animation(void * var, int32_t duration, int32_t delay, int32_t width, int32_t height, lv_anim_path_cb_t path_cb,
                        uint16_t repeat_cnt, uint32_t repeat_delay, uint32_t playback_time, uint32_t playback_delay,
                        lv_anim_start_cb_t start_cb, lv_anim_ready_cb_t ready_cb, lv_anim_deleted_cb_t deleted_cb);

void ui_img_zoom_animation(void * var, int32_t duration, int32_t delay, int32_t zoom, lv_anim_path_cb_t path_cb,
                           uint16_t repeat_cnt, uint32_t repeat_delay, uint32_t playback_time, uint32_t playback_delay,
                           lv_anim_start_cb_t start_cb, lv_anim_ready_cb_t ready_cb, lv_anim_deleted_cb_t deleted_cb);

void ui_img_rotate_animation(void * var, int32_t duration, int32_t delay, lv_coord_t x, lv_coord_t y, int32_t rotate,
                   lv_anim_path_cb_t path_cb, uint16_t repeat_cnt, uint32_t repeat_delay, uint32_t playback_time,
                   uint32_t playback_delay, lv_anim_start_cb_t start_cb, lv_anim_ready_cb_t ready_cb, lv_anim_deleted_cb_t deleted_cb);

void init_scr_del_flag(lv_ui *ui);

void setup_ui(lv_ui *ui);


extern lv_ui guider_ui;


void setup_scr_screen(lv_ui *ui);
LV_IMG_DECLARE(_Car_Unplugged_0_alpha_1277x797);
LV_IMG_DECLARE(_thermometeroutline_transparent_g_alpha_49x46);
LV_IMG_DECLARE(_flashoutline_transparent_steel_blue_alpha_47x54);
LV_IMG_DECLARE(_network_transparent_alpha_50x50);
LV_IMG_DECLARE(_locationsharp_transparent_alpha_30x29);
LV_IMG_DECLARE(_clouddone1_transparent_alpha_47x41);
LV_IMG_DECLARE(_Car_Unplugged_alpha_1280x800);
LV_IMG_DECLARE(_Car_plugged_alpha_1280x800);
LV_IMG_DECLARE(_cloudofflinesharp_transparent_gray29_alpha_47x41);
LV_IMG_DECLARE(_network_transparent_gray_alpha_50x50);
LV_IMG_DECLARE(_Designer_Manual_Edit_alpha_210x210);
LV_IMG_DECLARE(_arrow_green_alpha_80x67);
LV_IMG_DECLARE(_pngwing_close_alpha_51x51);

LV_FONT_DECLARE(lv_font_montserratMedium_30)
LV_FONT_DECLARE(lv_font_montserratMedium_16)
LV_FONT_DECLARE(lv_font_montserratMedium_51)
LV_FONT_DECLARE(lv_font_montserratMedium_18)
LV_FONT_DECLARE(lv_font_montserratMedium_12)
LV_FONT_DECLARE(lv_font_montserratMedium_20)
LV_FONT_DECLARE(lv_font_montserratMedium_25)
LV_FONT_DECLARE(lv_font_montserratMedium_40)
LV_FONT_DECLARE(lv_font_montserratMedium_45)
LV_FONT_DECLARE(lv_font_montserratMedium_12)
LV_FONT_DECLARE(lv_font_montserratMedium_29)
LV_FONT_DECLARE(lv_font_montserratMedium_24)
LV_FONT_DECLARE(lv_font_montserratMedium_75)
LV_FONT_DECLARE(lv_font_montserratMedium_53)
LV_FONT_DECLARE(lv_font_montserratMedium_21)
LV_FONT_DECLARE(lv_font_montserratMedium_16)
LV_FONT_DECLARE(lv_font_montserratMedium_17)
LV_FONT_DECLARE(lv_font_montserratMedium_13)
LV_FONT_DECLARE(lv_font_montserratMedium_22)
LV_FONT_DECLARE(lv_font_montserratMedium_37)
LV_FONT_DECLARE(lv_font_montserratMedium_94)


#ifdef __cplusplus
}
#endif
#endif
