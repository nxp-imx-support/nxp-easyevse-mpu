/*
* Copyright 2025 NXP
* NXP Confidential and Proprietary. This software is owned or controlled by NXP and may only be used strictly in
* accordance with the applicable license terms. By expressly accepting such terms or by downloading, installing,
* activating and/or otherwise using the software, you are agreeing that you have read, and that you agree to
* comply with and are bound by, such license terms.  If you do not agree to be bound by the applicable license
* terms, then you may not retain, install, activate or otherwise use the software.
*/

#include "events_init.h"
#include <stdio.h>
#include "lvgl.h"

#if LV_USE_FREEMASTER
#include "freemaster_client.h"
#endif


static void screen_img_3_event_handler (lv_event_t *e)
{
	lv_event_code_t code = lv_event_get_code(e);

	switch (code) {
	case LV_EVENT_CLICKED:
	{
		lv_obj_clear_flag(guider_ui.screen_label_13, LV_OBJ_FLAG_HIDDEN);
		lv_obj_clear_flag(guider_ui.screen_label_15, LV_OBJ_FLAG_HIDDEN);
		lv_obj_clear_flag(guider_ui.screen_label_16, LV_OBJ_FLAG_HIDDEN);
		break;
	}
	case LV_EVENT_LONG_PRESSED:
	{
		lv_obj_add_flag(guider_ui.screen_label_13, LV_OBJ_FLAG_HIDDEN);
		lv_obj_add_flag(guider_ui.screen_label_15, LV_OBJ_FLAG_HIDDEN);
		lv_obj_add_flag(guider_ui.screen_label_16, LV_OBJ_FLAG_HIDDEN);
		break;
	}
	default:
		break;
	}
}
static void screen_btn_1_event_handler (lv_event_t *e)
{
	lv_event_code_t code = lv_event_get_code(e);

	switch (code) {
	case LV_EVENT_CLICKED:
	{
		lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_Alatsi_Regular_69, 0);
		lv_label_set_text(guider_ui.screen_label_1, "EVSE Paused");
		break;
	}
	default:
		break;
	}
}
static void screen_btn_2_event_handler (lv_event_t *e)
{
	lv_event_code_t code = lv_event_get_code(e);

	switch (code) {
	case LV_EVENT_CLICKED:
	{
		lv_obj_set_style_text_font(guider_ui.screen_label_1, &lv_font_Alatsi_Regular_69, 0);
		lv_label_set_text(guider_ui.screen_label_1, "Charging");
		break;
	}
	default:
		break;
	}
}
static void screen_sw_2_event_handler (lv_event_t *e)
{
	lv_event_code_t code = lv_event_get_code(e);

	switch (code) {
	default:
		break;
	}
}
static void screen_sw_1_event_handler (lv_event_t *e)
{
	lv_event_code_t code = lv_event_get_code(e);

	switch (code) {
	default:
		break;
	}
}
static void screen_img_18_event_handler (lv_event_t *e)
{
	lv_event_code_t code = lv_event_get_code(e);

	switch (code) {
	case LV_EVENT_CLICKED:
	{
		lv_obj_add_flag(guider_ui.screen_img_18, LV_OBJ_FLAG_HIDDEN);
		lv_obj_clear_flag(guider_ui.screen_img_19, LV_OBJ_FLAG_HIDDEN);
		break;
	}
	default:
		break;
	}
}
static void screen_img_19_event_handler (lv_event_t *e)
{
	lv_event_code_t code = lv_event_get_code(e);

	switch (code) {
	case LV_EVENT_CLICKED:
	{
		lv_obj_clear_flag(guider_ui.screen_img_18, LV_OBJ_FLAG_HIDDEN);
		lv_obj_add_flag(guider_ui.screen_img_19, LV_OBJ_FLAG_HIDDEN);
		lv_obj_add_flag(guider_ui.screen_sw_2, LV_OBJ_FLAG_CHECKABLE);
		break;
	}
	default:
		break;
	}
}
static void screen_img_9_event_handler (lv_event_t *e)
{
	lv_event_code_t code = lv_event_get_code(e);

	switch (code) {
	case LV_EVENT_CLICKED:
	{
		lv_obj_add_flag(guider_ui.screen_cont_3, LV_OBJ_FLAG_HIDDEN);
		break;
	}
	default:
		break;
	}
}
void events_init_screen(lv_ui *ui)
{
	lv_obj_add_event_cb(ui->screen_img_3, screen_img_3_event_handler, LV_EVENT_ALL, ui);
	lv_obj_add_event_cb(ui->screen_btn_1, screen_btn_1_event_handler, LV_EVENT_ALL, ui);
	lv_obj_add_event_cb(ui->screen_btn_2, screen_btn_2_event_handler, LV_EVENT_ALL, ui);
	lv_obj_add_event_cb(ui->screen_sw_2, screen_sw_2_event_handler, LV_EVENT_ALL, ui);
	lv_obj_add_event_cb(ui->screen_sw_1, screen_sw_1_event_handler, LV_EVENT_ALL, ui);
	lv_obj_add_event_cb(ui->screen_img_18, screen_img_18_event_handler, LV_EVENT_ALL, ui);
	lv_obj_add_event_cb(ui->screen_img_19, screen_img_19_event_handler, LV_EVENT_ALL, ui);
	lv_obj_add_event_cb(ui->screen_img_9, screen_img_9_event_handler, LV_EVENT_ALL, ui);
}

void events_init(lv_ui *ui)
{

}
