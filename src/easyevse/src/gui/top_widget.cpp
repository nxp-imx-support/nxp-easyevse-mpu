/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/

#include "top_widget.h"
#include <QGridLayout>

#define DEBUG 0
static QString charging = ">   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   >   ";
static QString discharging = "<   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   <   ";
static QString tmp;

top_widget::top_widget(QWidget *parent)
    : QWidget{parent}
{
    charging.append(charging);
    discharging.append(discharging);
    tmp.reserve(256);
    count = 0;
    energy_mode_flag = "unknown";

    label_Charge_State.setText("Charge Sate");
    label_Power_Rate.setText("EVSE Rate");
    label_Auth_State.setText("Auth State");
    label_Charge_Cost.setText("Charge Cost");
    label_Charge_Current.setText("Current");
    label_EVSE_ID.setText("EVSE ID");
    label_Grid_Limit.setText("Grid Limit");
    label_Temperature.setText("Temperature");
    label_Remaining_Time.setText("Remian Time");
    label_Elapsed_Time.setText("Elapsed Time");

    //battery
    label_Vehicle_ID.setText("Vehicle ID");
    label_Requested_Energy.setText("Request");
    label_Delivered_Energy.setText("Delivered");
    label_Protocol.setText("Protocol");
    QProgressBar pb;

    //meter
    label_Mode.setText("Mode");
    label_VARh.setText("VARh");
    label_I_RMS.setText("I RMS");
    label_V_RMS.setText("V RMS");
    label_KW.setText("kW");
    label_Reactive.setText("Reactive");
    label_Active.setText("Active");
    label_Apparent.setText("Apparent");

    //discharging specified
    label_Transferred.setText("Transfer");
    label_DisChg_V.setText("DisChg_V");
    label_DisChg_I.setText("DisChg_I");

    Card_UID_icon.setStyleSheet(".QPushButton {"
                                 "     border-image: url(:/images/icon_lib/sc-id-card.svg);"
                                 "}");

    cloud_icon.setStyleSheet(".QPushButton {"
                             "     border-image: url(:/images/icon_lib/cloud-connectivity.svg);"
                             "}");

    evse_icon.setStyleSheet(".QPushButton {"
                             "     border-image: url(:/images/icon_lib/a-charge-station.svg);"
                             "}");

    ev_icon.setStyleSheet(".QPushButton {"
                             "     border-image: url(:/images/icon_lib/a-vehicle.svg);"
                             "}");

    meter_icon.setStyleSheet(".QPushButton {"
                             "     border-image: url(:/images/icon_lib/a-energy-charge.svg);"
                             "}");

    finger_icon.setStyleSheet(".QPushButton {"
                             "     border-image: url(:/images/icon_lib/hmi.svg);"
                             "}");

    setup_widget_main();

    connect(&timer, &QTimer::timeout, this, &top_widget::onTimeout);
    timer.start(300);

    connect(&mode_switch, &QPushButton::clicked, this, &top_widget::on_PushButton_Mode_Switch_clicked);
}

void top_widget::on_PushButton_Mode_Switch_clicked(){
    if(energy_mode_flag == "charging"){
        energy_mode_flag = "discharging";
        energy_mode.setStyleSheet(".QLabel{background-color: qlineargradient(spread: pad,x1:0,y1:0,x2:1,y2:0,stop:0 #00c,stop:1 #00f); "
                                  "       color: #bfb;"
                                  "}");
    }
    else if(energy_mode_flag == "discharging"){
        energy_mode_flag = "unknown";
        energy_mode.setStyleSheet(".QLabel{background-color: qlineargradient(spread: pad,x1:0,y1:0,x2:1,y2:0,stop:0 #bfb,stop:1 #bfb); "
                                  "       color: #bfb;"
                                  "}");
    }
    else {
        energy_mode_flag = "charging";
        energy_mode.setStyleSheet(".QLabel{background-color: qlineargradient(spread: pad,x1:0,y1:0,x2:1,y2:0,stop:0 #f80,stop:1 #f40); "
                                  "       color: #bfb;"
                                  "}");
    }

}

void top_widget::onTimeout()
{
    tmp = "";

    switch(count % 5)
    {
    case 0:
        tmp = "";
        break;
    case 1:
        tmp = " ";
        break;
    case 2:
        tmp = "  ";
        break;
    case 3:
        tmp = "   ";
        break;
    case 4:
        tmp = "    ";
        break;
    default:
        tmp = "unexpected error";
        break;
    }

    if(energy_mode_flag == "charging"){
        energy_mode.setStyleSheet(".QLabel{background-color: qlineargradient(spread: pad,x1:0,y1:0,x2:1,y2:0,stop:0 #f80,stop:1 #f40); "
                                  "       color: #bfb;"
                                  "}");
        tmp.append(charging);
        energy_mode.setText(tmp);
        count ++;
    }
    else if(energy_mode_flag == "discharging"){
        energy_mode.setStyleSheet(".QLabel{background-color: qlineargradient(spread: pad,x1:0,y1:0,x2:1,y2:0,stop:0 #00c,stop:1 #00f); "
                                  "       color: #bfb;"
                                  "}");
        tmp.append(discharging);
        energy_mode.setText(tmp);
        count --;
    }
    else {
	energy_mode.setStyleSheet(".QLabel{background-color: qlineargradient(spread: pad,x1:0,y1:0,x2:1,y2:0,stop:0 #bfb,stop:1 #bfb); "
                                  "       color: #bfb;"
                                  "}");
        energy_mode.setText("");
    }
#if DEBUG
    text_debug.setText(energy_mode_flag + " count: " + QString::number(count));
    pb.setValue(count % 100);
#endif
    if(energy_mode_flag != energy_mode_flag_old)
    {
        energy_mode_flag_old = energy_mode_flag;
        if(energy_mode_flag == "charging"){
            label_Requested_Energy.setVisible(true); lineEdit_Requested_Energy.setVisible(true);
            label_Delivered_Energy.setVisible(true); lineEdit_Delivered_Energy.setVisible(true);
            label_Charge_Current.setVisible(true); lineEdit_Charge_Current.setVisible(true);

            label_Remaining_Time.setVisible(true); lineEdit_Remaining_Time.setVisible(true);
            label_Charge_Cost.setVisible(true); lineEdit_Charge_Cost.setVisible(true);

            label_Transferred.setVisible(false); lineEdit_Transferred.setVisible(false);
            label_DisChg_V.setVisible(false); lineEdit_DisChg_V.setVisible(false);
            label_DisChg_I.setVisible(false); lineEdit_DisChg_I.setVisible(false);
        }
        else if(energy_mode_flag == "discharging"){
            label_Requested_Energy.setVisible(false); lineEdit_Requested_Energy.setVisible(false);
            label_Delivered_Energy.setVisible(false); lineEdit_Delivered_Energy.setVisible(false);
            label_Charge_Current.setVisible(false); lineEdit_Charge_Current.setVisible(false);

            label_Remaining_Time.setVisible(false); lineEdit_Remaining_Time.setVisible(false);
            label_Charge_Cost.setVisible(false); lineEdit_Charge_Cost.setVisible(false);

            label_Transferred.setVisible(true); lineEdit_Transferred.setVisible(true);
            label_DisChg_V.setVisible(true); lineEdit_DisChg_V.setVisible(true);
            label_DisChg_I.setVisible(true); lineEdit_DisChg_I.setVisible(true);
        }
        else {
            label_Requested_Energy.setVisible(false); lineEdit_Requested_Energy.setVisible(false);
            label_Delivered_Energy.setVisible(false); lineEdit_Delivered_Energy.setVisible(false);
            label_Charge_Current.setVisible(false); lineEdit_Charge_Current.setVisible(false);

            label_Remaining_Time.setVisible(false); lineEdit_Remaining_Time.setVisible(false);
            label_Charge_Cost.setVisible(false); lineEdit_Charge_Cost.setVisible(false);

            label_Transferred.setVisible(false); lineEdit_Transferred.setVisible(false);
            label_DisChg_V.setVisible(false); lineEdit_DisChg_V.setVisible(false);
            label_DisChg_I.setVisible(false); lineEdit_DisChg_I.setVisible(false);
        }
    }
}
top_widget::~top_widget()
{

}

void top_widget::setup_widget_main()
{
    this->setAttribute(Qt::WA_StyledBackground);

    this->setLayout(&layout_main_v);
    this->setStyleSheet("top_widget { background-color: qlineargradient(spread: pad,x1:0,y1:0,x2:0,y2:1,stop:0 #efe,stop:1 #8f8); }"
                        "QLineEdit { border: none; min-width: 1; color: #448; "
			"	     background-color: qradialgradient(cx:0.5,cy:0.5,radius:1,fx:0.5,fy:0.5,stop:0 #fff,stop:1 #afa); }"
                        "QLabel { color: #555; }"
                        );

    text_license.setText("Uses LGPL-3.0 libraries");
    text_license.setStyleSheet("QLineEdit { border: none; color: #000; background-color: #8f8; }");
    text_license.setAlignment(Qt::AlignRight); text_license.setReadOnly(true);

    layout_main_v.addWidget(&frame1); frame1.setFrameStyle(QFrame::Box | QFrame::Raised); frame1.setLayout(&layout_main_menu);
    layout_main_v.addStretch(3);
    layout_main_v.addLayout(&layout_main_evse_ev, 8);layout_main_evse_ev.setAlignment(Qt::AlignCenter);
    layout_main_v.addStretch(2);
    layout_main_v.addLayout(&layout_main_bottom, 3);layout_main_bottom.setAlignment(Qt::AlignBottom);
    layout_main_v.addStretch(1);
#if DEBUG
    layout_main_v.addWidget(&text_debug);
#endif
    layout_main_v.addWidget(&text_license);

    layout_main_menu.addWidget(&Card_UID_icon); layout_main_menu.addWidget(&lineEdit_Card_UID);
    layout_main_menu.addStretch(1);
    layout_main_menu.addWidget(&label_Temperature); layout_main_menu.addWidget(&lineEdit_Temperature);
    layout_main_menu.addWidget(&cloud_icon);

    layout_main_evse_ev.addWidget(&evse_icon);
    layout_main_evse_ev.addLayout(&layout_main_evse_ev_v1);
    layout_main_evse_ev.addLayout(&layout_main_evse_ev_v2);
    layout_main_evse_ev_v2.addLayout(&layout_main_evse_ev_h1);
    layout_main_evse_ev_h1.addWidget(&pb);
    layout_main_evse_ev_v2.addWidget(&ev_icon);
    layout_main_evse_ev_v1.addLayout(&layout_main_evse_ev_h2);
    layout_main_evse_ev_g1.addWidget(&label_EVSE_ID, 0, 0); layout_main_evse_ev_g1.addWidget(&lineEdit_EVSE_ID, 0, 1);
    layout_main_evse_ev_g1.addWidget(&label_Auth_State, 1, 0); layout_main_evse_ev_g1.addWidget(&lineEdit_Auth_State, 1, 1);
    layout_main_evse_ev_g1.addWidget(&label_Power_Rate, 2, 0); layout_main_evse_ev_g1.addWidget(&lineEdit_Power_Rate, 2, 1);
    layout_main_evse_ev_g1.addWidget(&label_Grid_Limit, 3, 0); layout_main_evse_ev_g1.addWidget(&lineEdit_Grid_Limit, 3, 1);
    layout_main_evse_ev_g1.addWidget(&label_Delivered_Energy, 4, 0); layout_main_evse_ev_g1.addWidget(&lineEdit_Delivered_Energy, 4, 1);
    layout_main_evse_ev_g1.addWidget(&label_Transferred, 5, 0); layout_main_evse_ev_g1.addWidget(&lineEdit_Transferred, 5, 1);

    layout_main_evse_ev_g2.addWidget(&label_Vehicle_ID, 0, 0); layout_main_evse_ev_g2.addWidget(&lineEdit_Vehicle_ID, 0, 1);
    layout_main_evse_ev_g2.addWidget(&label_Mode, 1, 0); layout_main_evse_ev_g2.addWidget(&lineEdit_Mode, 1, 1);
    layout_main_evse_ev_g2.addWidget(&label_Protocol, 2, 0); layout_main_evse_ev_g2.addWidget(&lineEdit_Protocol, 2, 1);
    layout_main_evse_ev_g2.addWidget(&label_Charge_Current, 3, 0); layout_main_evse_ev_g2.addWidget(&lineEdit_Charge_Current, 3, 1);
    layout_main_evse_ev_g2.addWidget(&label_Requested_Energy, 4, 0); layout_main_evse_ev_g2.addWidget(&lineEdit_Requested_Energy, 4, 1);
    layout_main_evse_ev_g2.addWidget(&label_DisChg_V, 6, 0); layout_main_evse_ev_g2.addWidget(&lineEdit_DisChg_V, 6, 1);
    layout_main_evse_ev_g2.addWidget(&label_DisChg_I, 7, 0); layout_main_evse_ev_g2.addWidget(&lineEdit_DisChg_I, 7, 1);

    layout_main_evse_ev_h2.addStretch(1);
    layout_main_evse_ev_h2.addWidget(&frame2); frame2.setFrameStyle(QFrame::Box | QFrame::Sunken); frame2.setLayout(&layout_main_evse_ev_g1);
    layout_main_evse_ev_h2.addStretch(1);
    layout_main_evse_ev_h2.addWidget(&frame3); frame3.setFrameStyle(QFrame::Box | QFrame::Sunken); frame3.setLayout(&layout_main_evse_ev_g2);
    layout_main_evse_ev_h2.addStretch(1);
    layout_main_evse_ev_v1.addStretch(1);
    layout_main_evse_ev_v1.addLayout(&layout_main_evse_ev_h3);
    layout_main_evse_ev_h3.addWidget(&energy_mode);
    layout_main_evse_ev_v1.addStretch(1);

    layout_main_bottom.addStretch(1);
    layout_main_bottom.addWidget(&frame4); frame4.setFrameStyle(QFrame::Box | QFrame::Raised); frame4.setLayout(&layout_main_meter);
    layout_main_bottom.addStretch(1);
    layout_main_bottom.addWidget(&frame5); frame5.setFrameStyle(QFrame::Box | QFrame::Raised); frame5.setLayout(&layout_main_meter_g3);
    layout_main_bottom.addStretch(1);
    layout_main_bottom.addWidget(&frame6); frame6.setFrameStyle(QFrame::Box | QFrame::Raised); frame6.setLayout(&layout_main_control);
    layout_main_bottom.addStretch(1);

    layout_main_meter.addWidget(&meter_icon);
    layout_main_meter.addStretch(1);
    layout_main_meter.addLayout(&layout_main_meter_g1);
    layout_main_meter.addStretch(1);
    layout_main_meter_g1.addWidget(&label_VARh, 0, 0); layout_main_meter_g1.addWidget(&lineEdit_VARh, 0, 1);
    layout_main_meter_g1.addWidget(&label_I_RMS, 1, 0); layout_main_meter_g1.addWidget(&lineEdit_I_RMS, 1, 1);
    layout_main_meter_g1.addWidget(&label_V_RMS, 2, 0); layout_main_meter_g1.addWidget(&lineEdit_V_RMS, 2, 1);
    layout_main_meter_g1.addWidget(&label_KW, 3, 0); layout_main_meter_g1.addWidget(&lineEdit_KW, 3, 1);
    layout_main_meter.addLayout(&layout_main_meter_g2);
    layout_main_meter.addStretch(1);

    layout_main_meter_g2.addWidget(&label_Active, 0, 0); layout_main_meter_g2.addWidget(&lineEdit_Active, 0, 1);
    layout_main_meter_g2.addWidget(&label_Reactive, 1, 0); layout_main_meter_g2.addWidget(&lineEdit_Reactive, 1, 1);
    layout_main_meter_g2.addWidget(&label_Apparent, 2, 0); layout_main_meter_g2.addWidget(&lineEdit_Apparent, 2, 1);

    layout_main_meter_g3.addWidget(&label_Elapsed_Time, 0, 0); layout_main_meter_g3.addWidget(&lineEdit_Elapsed_Time, 0, 1);
    layout_main_meter_g3.addWidget(&label_Remaining_Time, 1, 0); layout_main_meter_g3.addWidget(&lineEdit_Remaining_Time, 1, 1);
    layout_main_meter_g3.addWidget(&label_Charge_Cost, 2, 0); layout_main_meter_g3.addWidget(&lineEdit_Charge_Cost, 2, 1);

    layout_main_control.addLayout(&layout_main_control_h);
    layout_main_control_h.addWidget(&finger_icon);
    layout_main_control_h.addLayout(&layout_main_control_v1);
    layout_main_control_v1.addWidget(&btn_pause_resume);
    layout_main_control_v1.addWidget(&mode_switch);
}


void top_widget::resizeEvent(QResizeEvent *event)
{
    QFont font, font_item, font_content, font_button;
    QSize size = this->size();
    int width = size.width();
    int height = size.height();
    float f_w = width / 1280.0;
    float f_h = height / 800.0;
    float factor = qMin(f_w, f_h);

    qDebug() << "resize" << size.width() << size.height();

    font_item.setFamily("Sans Serif");
    font_item.setPixelSize(f_w * 20);
    font_item.setBold(true);
    font_content.setFamily("Sans Serif");
    font_content.setPixelSize(f_w * 20);
    font_content.setBold(false);

    label_EVSE_ID.setFont(font_item); lineEdit_EVSE_ID.setFont(font_content); lineEdit_EVSE_ID.setReadOnly(true);
    label_Charge_State.setFont(font_item); lineEdit_Charge_State.setFont(font_content); lineEdit_Charge_State.setReadOnly(true);
    lineEdit_Card_UID.setFont(font_content); lineEdit_Card_UID.setReadOnly(true);

    Card_UID_icon.setFixedSize(font_item.pixelSize() * 1.1, font_item.pixelSize());
    cloud_icon.setFixedSize(font_item.pixelSize() * 1.2, font_item.pixelSize());

    evse_icon.setFixedSize(factor * 300 * 0.9, factor * 350);
    ev_icon.setFixedSize(factor * 300 * 0.9, factor* 300);
    meter_icon.setFixedSize(factor * 150 * 0.75, factor * 150);
    finger_icon.setFixedSize(factor * 70 * 0.75, factor * 70);
    btn_pause_resume.setFont(font_item);
    label_Auth_State.setFont(font_item);
    label_Power_Rate.setFont(font_item);
    label_Grid_Limit.setFont(font_item);
    label_Temperature.setFont(font_item);
    label_Charge_Current.setFont(font_item);
    lineEdit_Auth_State.setFont(font_content); lineEdit_Auth_State.setReadOnly(true);
    lineEdit_Power_Rate.setFont(font_content); lineEdit_Power_Rate.setReadOnly(true);
    lineEdit_Grid_Limit.setFont(font_content); lineEdit_Grid_Limit.setReadOnly(true);
    lineEdit_Temperature.setFont(font_content); lineEdit_Temperature.setReadOnly(true);
    lineEdit_Charge_Current.setFont(font_content); lineEdit_Charge_Current.setReadOnly(true);

    label_Vehicle_ID.setFont(font_item);
    label_Requested_Energy.setFont(font_item);
    label_Delivered_Energy.setFont(font_item);
    label_Mode.setFont(font_item);
    label_Protocol.setFont(font_item);
    lineEdit_Vehicle_ID.setFont(font_content); lineEdit_Vehicle_ID.setReadOnly(true);
    lineEdit_Requested_Energy.setFont(font_content); lineEdit_Requested_Energy.setReadOnly(true);
    lineEdit_Delivered_Energy.setFont(font_content); lineEdit_Delivered_Energy.setReadOnly(true);
    lineEdit_Mode.setFont(font_content); lineEdit_Mode.setReadOnly(true);
    lineEdit_Protocol.setFont(font_content); lineEdit_Protocol.setReadOnly(true);

    label_VARh.setFont(font_item);
    label_I_RMS.setFont(font_item);
    label_V_RMS.setFont(font_item);
    label_KW.setFont(font_item);
    label_Active.setFont(font_item);
    label_Reactive.setFont(font_item);
    label_Apparent.setFont(font_item);
    lineEdit_VARh.setFont(font_content); lineEdit_VARh.setReadOnly(true);
    lineEdit_I_RMS.setFont(font_content); lineEdit_I_RMS.setReadOnly(true);
    lineEdit_V_RMS.setFont(font_content); lineEdit_V_RMS.setReadOnly(true);
    lineEdit_KW.setFont(font_content); lineEdit_KW.setReadOnly(true);
    lineEdit_Active.setFont(font_content); lineEdit_Active.setReadOnly(true);
    lineEdit_Reactive.setFont(font_content); lineEdit_Reactive.setReadOnly(true);
    lineEdit_Apparent.setFont(font_content); lineEdit_Apparent.setReadOnly(true);

    label_Elapsed_Time.setFont(font_item); lineEdit_Elapsed_Time.setFont(font_content); lineEdit_Elapsed_Time.setReadOnly(true);
    label_Remaining_Time.setFont(font_item); lineEdit_Remaining_Time.setFont(font_content); lineEdit_Remaining_Time.setReadOnly(true);
    label_Charge_Cost.setFont(font_item); lineEdit_Charge_Cost.setFont(font_content); lineEdit_Charge_Cost.setReadOnly(true);

    label_Transferred.setFont(font_item); lineEdit_Transferred.setFont(font_content); lineEdit_Transferred.setReadOnly(true);
    label_DisChg_V.setFont(font_item); lineEdit_DisChg_V.setFont(font_content); lineEdit_DisChg_V.setReadOnly(true);
    label_DisChg_I.setFont(font_item); lineEdit_DisChg_I.setFont(font_content); lineEdit_DisChg_I.setReadOnly(true);


    energy_mode.setFixedSize(width - evse_icon.width() * 2.25, font_item.pixelSize());
    font.setPixelSize(font_item.pixelSize() * 2.5);
    energy_mode.setFont(font);

    font.setBold(true);
    font.setPixelSize(factor * 20);
    btn_pause_resume.setFont(font);
    btn_pause_resume.setFixedSize(factor * 100, factor * 100);
    QString ccs = QString("QPushButton { border-radius: %1px; background-color: #dd0; }").arg(factor * 50 - 1);
    btn_pause_resume.setStyleSheet(ccs);
    btn_pause_resume.setText("PAUSE");

    pb.setFixedWidth(ev_icon.width() * 0.8);
    font_content.setPixelSize(f_w * 15);
    text_license.setFont(font_content);
#if DEBUG
    text_debug.setFont(font_content);
#endif

}
