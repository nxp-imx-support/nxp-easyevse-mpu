/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/

#include "top_stackedwidget.h"
#include <QGridLayout>


top_stackedwidget::top_stackedwidget(QStackedWidget *parent)
    : QStackedWidget{parent}
{
    //status
    label_0.setText("EVSE Status");
    label_1.setText("Charge Sate");
    label_2.setText("Power Rate");
    label_3.setText("Auth State");
    label_4.setText("Charge Cost");
    label_5.setText("Charge Current");
    label_6.setText("EVSE ID");
    label_7.setText("Grid Limit");
    label_8.setText("Temperature");
    label_9.setText("Time to Charge");
    label_10.setText("Elapsed Time");

    //battery
    label_20.setText("Vehicle Settings");
    label_21.setText("Vehicle ID");
    label_22.setText("Requested Energy");
    label_23.setText("Delivered Energy");
    label_24.setText("Protocol");

    //meter
    label_40.setText("Meter Menu");
    label_41.setText("Mode");
    label_42.setText("VARh");
    label_43.setText("I RMS");
    label_44.setText("V RMS");
    label_45.setText("KW");
    label_46.setText("Reactive");
    label_47.setText("Active");
    label_48.setText("Apparent");

    //nfc
    label_60.setText("NFC Card");
    label_61.setText("Card UID");

    setup_widget_main();
    setup_widget_status();
    setup_widget_battery();
    setup_widget_meter();
    setup_widget_nfc();

    this->addWidget(&widget_main);
    this->addWidget(&widget_status);
    this->addWidget(&widget_battery);
    this->addWidget(&widget_meter);
    this->addWidget(&widget_nfc);

    this->setCurrentIndex(0);

}

top_stackedwidget::~top_stackedwidget()
{

}

void top_stackedwidget::setup_widget_main()
{
    layout_main.setContentsMargins(60, 60, 60, 60);

    layout_main.addWidget(&btn_status, 1, 1, 1, 3, Qt::AlignCenter);
    layout_main.addWidget(&btn_battery, 2, 1, 1, 3, Qt::AlignCenter);
    layout_main.addWidget(&btn_meter, 1, 4, 1, 3, Qt::AlignCenter);
    layout_main.addWidget(&btn_nfc, 2, 4, 1, 3, Qt::AlignCenter);

    text_license.setText("Uses LGPL-3.0 libraries");
    text_license.setParent(&widget_main);
    text_license.setStyleSheet("QLineEdit { border: none; }");

    widget_main.setLayout(&layout_main);
    widget_main.setStyleSheet(".QWidget {border-image: url(:/images/mainpng.png);}");

    btn_status.setFixedSize(60, 60);
    btn_battery.setFixedSize(60, 60);
    btn_meter.setFixedSize(60, 60);
    btn_nfc.setFixedSize(60, 60);
    btn_status.setStyleSheet("QPushButton {"
                              "     border-image: url(:/images/third-party/car-solid.svg);"
                              "     border-radius: 30px;"
                              "     background: qradialgradient("
                              "         cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "         radius: 1.35, stop: 0 #fff, stop: 1 #fff"
                              "     );"
                              "     padding: 60px;"
                              "}"
                              "QPushButton:hover {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #bbb"
                              "     );"
                              "}"
                              "QPushButton:pressed {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #888"
                              "     );"
                              "}");
    btn_battery.setStyleSheet("QPushButton {"
                              "     border-image: url(:/images/third-party/car-battery-solid.svg);"
                              "     border-radius: 30px;"
                              "     background: qradialgradient("
                              "         cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "         radius: 1.35, stop: 0 #fff, stop: 1 #fff"
                              "     );"
                              "     padding: 60px;"
                              "}"
                              "QPushButton:hover {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #bbb"
                              "     );"
                              "}"
                              "QPushButton:pressed {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #888"
                              "     );"
                              "}");
    btn_meter.setStyleSheet("QPushButton {"
                              "     border-image: url(:/images/third-party/bolt-solid.svg);"
                              "     border-radius: 30px;"
                              "     background: qradialgradient("
                              "         cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "         radius: 1.35, stop: 0 #fff, stop: 1 #fff"
                              "     );"
                              "     padding: 60px;"
                              "}"
                              "QPushButton:hover {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #bbb"
                              "     );"
                              "}"
                              "QPushButton:pressed {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #888"
                              "     );"
                              "}");
    btn_nfc.setStyleSheet("QPushButton {"
                              "     border-image: url(:/images/third-party/id-card-solid.svg);"
                              "     border-radius: 30px;"
                              "     background: qradialgradient("
                              "         cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "         radius: 1.35, stop: 0 #fff, stop: 1 #fff"
                              "     );"
                              "     padding: 60px;"
                              "}"
                              "QPushButton:hover {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #bbb"
                              "     );"
                              "}"
                              "QPushButton:pressed {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #888"
                              "     );"
                              "}");
    connect(&btn_status, &QPushButton::clicked, [=](){
        this->setCurrentIndex(1);
    });
    connect(&btn_battery, &QPushButton::clicked, [=](){
        this->setCurrentIndex(2);
    });
    connect(&btn_meter, &QPushButton::clicked, [=](){
        this->setCurrentIndex(3);
    });
    connect(&btn_nfc, &QPushButton::clicked, [=](){
        this->setCurrentIndex(4);
    });
}

void top_stackedwidget::setup_widget_status()
{
    layout_status_v.setContentsMargins(60, 60, 60, 60);
    layout_status_h_1.setContentsMargins(0, 0, 0, 60);
    layout_status_g_1.setContentsMargins(0, 0, 30, 0);
    layout_status_g_2.setContentsMargins(30, 0, 0, 0);
    layout_status_v.addLayout(&layout_status_h_1);
    layout_status_v.addStretch(1);
    layout_status_v.addLayout(&layout_status_h_2);
    layout_status_v.addStretch(1);
    layout_status_v.setAlignment(Qt::AlignTop);
    layout_status_h_1.addWidget(&label_0);
    layout_status_h_1.addWidget(&btn_back_1);
    layout_status_h_2.addLayout(&layout_status_g_1);
    layout_status_h_2.addLayout(&layout_status_g_2);
    layout_status_g_1.addWidget(&label_1, 1, 1);
    layout_status_g_1.addWidget(&lineEdit_Charge_State, 1, 2);
    layout_status_g_1.addWidget(&label_2, 2, 1);
    layout_status_g_1.addWidget(&lineEdit_Power_Rate, 2, 2);
    layout_status_g_1.addWidget(&label_3, 3, 1);
    layout_status_g_1.addWidget(&lineEdit_Auth_State, 3, 2);
    layout_status_g_1.addWidget(&label_4, 4, 1);
    layout_status_g_1.addWidget(&lineEdit_Charge_Cost, 4, 2);
    layout_status_g_1.addWidget(&label_5, 5, 1);
    layout_status_g_1.addWidget(&lineEdit_Charge_Current, 5, 2);
    layout_status_g_2.addWidget(&label_6, 1, 1);
    layout_status_g_2.addWidget(&lineEdit_EVSE_ID, 1, 2);
    layout_status_g_2.addWidget(&label_7, 2, 1);
    layout_status_g_2.addWidget(&lineEdit_Grid_Limit, 2, 2);
    layout_status_g_2.addWidget(&label_8, 3, 1);
    layout_status_g_2.addWidget(&lineEdit_Temperature, 3, 2);
    layout_status_g_2.addWidget(&label_9, 4, 1);
    layout_status_g_2.addWidget(&lineEdit_Time2Charge, 4, 2);
    layout_status_g_2.addWidget(&label_10, 5, 1);
    layout_status_g_2.addWidget(&lineEdit_Elapsed_Time, 5, 2);

    widget_status.setLayout(&layout_status_v);
    widget_status.setStyleSheet(".QWidget {border-image: url(:/images/plainpng.png);}");

    btn_back_1.setFixedSize(QSize(70, 70));
    btn_back_1.setStyleSheet("QPushButton{"
                              "     border-image: url(:/images/third-party/circle-arrow-left-solid.svg);"
                              "     border-radius: 95px;"
                              "     background: qradialgradient("
                              "         cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "         radius: 1.35, stop: 0 #fff, stop: 1 #fff"
                              "     );"
                              "     padding: 5px;"
                              "}"
                              "QPushButton:hover {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #bbb"
                              "     );"
                              "}"
                              "QPushButton:pressed {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #ddd"
                              "     );"
                              "}");
    connect(&btn_back_1, &QPushButton::clicked, [=](){
        this->setCurrentIndex(0);
    });
}

void top_stackedwidget::setup_widget_battery()
{
    layout_battery_v.setContentsMargins(60, 60, 60, 60);
    layout_battery_h.setContentsMargins(0, 0, 0, 60);
    layout_battery_g.setContentsMargins(200, 0, 200, 0);

    layout_battery_v.addLayout(&layout_battery_h);
    layout_battery_v.addStretch(1);
    layout_battery_v.addLayout(&layout_battery_g);
    layout_battery_v.addStretch(1);
    pb.setRange(0,100);
    pb.setValue(0);
    layout_battery_v.addStretch(1);
    layout_battery_v.setAlignment(Qt::AlignTop);
    layout_battery_h.addWidget(&label_20);
    layout_battery_h.addWidget(&btn_back_2);
    layout_battery_g.addWidget(&label_21, 1, 1);
    layout_battery_g.addWidget(&lineEdit_Vehicle_ID, 1, 2);
    layout_battery_g.addWidget(&label_22, 2, 1);
    layout_battery_g.addWidget(&lineEdit_Requested_Energy, 2, 2);
    layout_battery_g.addWidget(&label_23, 3, 1);
    layout_battery_g.addWidget(&lineEdit_Delivered_Energy, 3, 2);
    layout_battery_g.addWidget(&label_24, 4, 1);
    layout_battery_g.addWidget(&lineEdit_Protocol, 4, 2);

    widget_battery.setLayout(&layout_battery_v);
    widget_battery.setStyleSheet(".QWidget {border-image: url(:/images/plainpng.png);}");

    btn_back_2.setFixedSize(QSize(70, 70));
    btn_back_2.setStyleSheet("QPushButton{"
                              "     border-image: url(:/images/third-party/circle-arrow-left-solid.svg);"
                              "     border-radius: 95px;"
                              "     background: qradialgradient("
                              "         cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "         radius: 1.35, stop: 0 #fff, stop: 1 #fff"
                              "     );"
                              "     padding: 5px;"
                              "}"
                              "QPushButton:hover {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #bbb"
                              "     );"
                              "}"
                              "QPushButton:pressed {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #ddd"
                              "     );"
                              "}");
    connect(&btn_back_2, &QPushButton::clicked, [=](){
        this->setCurrentIndex(0);
    });
}

void top_stackedwidget::setup_widget_meter()
{
    layout_meter_v.setContentsMargins(60, 60, 60, 60);
    layout_meter_h_1.setContentsMargins(0, 0, 0, 60);
    layout_meter_g_1.setContentsMargins(30, 0, 30, 0);
    layout_meter_g_2.setContentsMargins(30, 0, 30, 0);
    layout_meter_v.addLayout(&layout_meter_h_1);
    layout_meter_v.addStretch(1);
    layout_meter_v.addLayout(&layout_meter_h_2);
    layout_meter_v.addStretch(1);
    layout_meter_v.setAlignment(Qt::AlignTop);
    layout_meter_h_1.addWidget(&label_40);
    layout_meter_h_1.addWidget(&btn_back_3);
    layout_meter_h_2.addLayout(&layout_meter_g_1);
    layout_meter_h_2.addLayout(&layout_meter_g_2);
    layout_meter_g_1.addWidget(&label_41, 1, 1);
    layout_meter_g_1.addWidget(&lineEdit_Mode, 1, 2);
    layout_meter_g_1.addWidget(&label_42, 2, 1);
    layout_meter_g_1.addWidget(&lineEdit_VARh, 2, 2);
    layout_meter_g_1.addWidget(&label_43, 3, 1);
    layout_meter_g_1.addWidget(&lineEdit_I_RMS, 3, 2);
    layout_meter_g_1.addWidget(&label_44, 4, 1);
    layout_meter_g_1.addWidget(&lineEdit_V_RMS, 4, 2);
    layout_meter_g_2.addWidget(&label_45, 1, 1);
    layout_meter_g_2.addWidget(&lineEdit_KW, 1, 2);
    layout_meter_g_2.addWidget(&label_46, 2, 1);
    layout_meter_g_2.addWidget(&lineEdit_Reactive, 2, 2);
    layout_meter_g_2.addWidget(&label_47, 3, 1);
    layout_meter_g_2.addWidget(&lineEdit_Active, 3, 2);
    layout_meter_g_2.addWidget(&label_48, 4, 1);
    layout_meter_g_2.addWidget(&lineEdit_Apparent, 4, 2);

    widget_meter.setLayout(&layout_meter_v);
    widget_meter.setStyleSheet(".QWidget {border-image: url(:/images/plainpng.png);}");

    btn_back_3.setFixedSize(QSize(70, 70));
    btn_back_3.setStyleSheet("QPushButton{"
                              "     border-image: url(:/images/third-party/circle-arrow-left-solid.svg);"
                              "     border-radius: 95px;"
                              "     background: qradialgradient("
                              "         cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "         radius: 1.35, stop: 0 #fff, stop: 1 #fff"
                              "     );"
                              "     padding: 5px;"
                              "}"
                              "QPushButton:hover {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #bbb"
                              "     );"
                              "}"
                              "QPushButton:pressed {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #ddd"
                              "     );"
                              "}");
    connect(&btn_back_3, &QPushButton::clicked, [=](){
        this->setCurrentIndex(0);
    });
}

void top_stackedwidget::setup_widget_nfc()
{
    layout_nfc_v.setContentsMargins(60, 60, 60, 60);
    layout_nfc_g.setContentsMargins(200, 0, 200, 0);

    layout_nfc_v.addLayout(&layout_nfc_h);
    layout_nfc_v.addStretch(3);
    layout_nfc_v.addLayout(&layout_nfc_g);
    layout_nfc_v.addStretch(2);
    layout_nfc_v.setAlignment(Qt::AlignTop);
    layout_nfc_h.addWidget(&label_60);
    layout_nfc_h.addWidget(&btn_back_4);
    layout_nfc_g.addWidget(&label_61, 1, 1);
    layout_nfc_g.addWidget(&lineEdit_Card_UID, 2, 1);

    widget_nfc.setLayout(&layout_nfc_v);
    widget_nfc.setStyleSheet(".QWidget {border-image: url(:/images/plainpng.png);}");

    btn_back_4.setFixedSize(QSize(70, 70));
    btn_back_4.setStyleSheet("QPushButton{"
                              "     border-image: url(:/images/third-party/circle-arrow-left-solid.svg);"
                              "     border-radius: 95px;"
                              "     background: qradialgradient("
                              "         cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "         radius: 1.35, stop: 0 #fff, stop: 1 #fff"
                              "     );"
                              "     padding: 5px;"
                              "}"
                              "QPushButton:hover {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.3, cy: -0.4, fx: 0.3, fy: -0.4,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #bbb"
                              "     );"
                              "}"
                              "QPushButton:pressed {"
                              "     border-style: inset;"
                              "     background: qradialgradient("
                              "     cx: 0.4, cy: -0.1, fx: 0.4, fy: -0.1,"
                              "     radius: 1.35, stop: 0 #fff, stop: 1 #ddd"
                              "     );"
                              "}");
    connect(&btn_back_4, &QPushButton::clicked, [=](){
        this->setCurrentIndex(0);
    });
}

void top_stackedwidget::resizeEvent(QResizeEvent *event)
{
    QSize size = this->size();
    int width = qMin(size.width(), size.height()) * 0.38;
    qDebug() << "resize" << size.width() << size.height() << width;
    btn_status.setFixedSize(QSize(width, width));
    btn_battery.setFixedSize(QSize(width, width));
    btn_meter.setFixedSize(QSize(width, width));
    btn_nfc.setFixedSize(QSize(width, width));
    layout_main.setContentsMargins(width / 2, 0, width / 2, 0);

    int margin_1 = size.width() / 8;
    int margin_2 = size.height() / 8;
    layout_status_v.setContentsMargins(margin_1, margin_2, margin_1, margin_2);
    layout_battery_v.setContentsMargins(margin_1, margin_2, margin_1, margin_2);
    layout_meter_v.setContentsMargins(margin_1, margin_2, margin_1, margin_2);
    layout_nfc_v.setContentsMargins(margin_1, margin_2, margin_1, margin_2);

    btn_back_1.setFixedSize(QSize(0.1 * size.width(), 0.1 * size.width()));
    btn_back_2.setFixedSize(QSize(0.1 * size.width(), 0.1 * size.width()));
    btn_back_3.setFixedSize(QSize(0.1 * size.width(), 0.1 * size.width()));
    btn_back_4.setFixedSize(QSize(0.1 * size.width(), 0.1 * size.width()));

    font_title.setFamily("Sans Serif");
    font_table.setFamily("Sans Serif");
    font_table2.setFamily("Sans Serif");
    font_license.setFamily("Sans Serif");

    font_title.setPixelSize(0.06 * size.width());
    font_table.setPixelSize(0.02 * size.width());
    font_table2.setPixelSize(0.015 * size.width());
    font_license.setPixelSize(0.01 * size.width());

    text_license.setFont(font_license); text_license.setReadOnly(true);
    text_license.setFixedWidth(text_license.fontMetrics().boundingRect(text_license.text()).width() * 1.1);
    text_license.setFixedHeight(text_license.fontMetrics().boundingRect(text_license.text()).height() * 1.1);
    text_license.setGeometry(0.85 * size.width(), 0.9 * size.height(), text_license.width(), text_license.height());

    label_0.setFont(font_title); label_0.setAlignment(Qt::AlignCenter);
    label_1.setFont(font_table);
    label_2.setFont(font_table);
    label_3.setFont(font_table);
    label_4.setFont(font_table);
    label_5.setFont(font_table);
    label_6.setFont(font_table);
    label_7.setFont(font_table);
    label_8.setFont(font_table);
    label_9.setFont(font_table);
    label_10.setFont(font_table);
    lineEdit_Charge_State.setFont(font_table2); lineEdit_Charge_State.setReadOnly(true);
    lineEdit_Charge_State.setStyleSheet("QLineEdit {background-color: #eee; border: 0px;}");
    lineEdit_Power_Rate.setFont(font_table2); lineEdit_Power_Rate.setReadOnly(true);
    lineEdit_Auth_State.setFont(font_table2); lineEdit_Auth_State.setReadOnly(true);
    lineEdit_Charge_Cost.setFont(font_table2); lineEdit_Charge_Cost.setReadOnly(true);
    lineEdit_Charge_Current.setFont(font_table2); lineEdit_Charge_Current.setReadOnly(true);
    lineEdit_EVSE_ID.setFont(font_table2); lineEdit_EVSE_ID.setReadOnly(true);
    lineEdit_Grid_Limit.setFont(font_table2); lineEdit_Grid_Limit.setReadOnly(true);
    lineEdit_Temperature.setFont(font_table2); lineEdit_Temperature.setReadOnly(true);
    lineEdit_Time2Charge.setFont(font_table2); lineEdit_Time2Charge.setReadOnly(true);
    lineEdit_Elapsed_Time.setFont(font_table2); lineEdit_Elapsed_Time.setReadOnly(true);

    label_20.setFont(font_title); label_20.setAlignment(Qt::AlignCenter);
    label_21.setFont(font_table);
    label_22.setFont(font_table);
    label_23.setFont(font_table);
    label_24.setFont(font_table);
    lineEdit_Vehicle_ID.setFont(font_table2); lineEdit_Vehicle_ID.setReadOnly(true); lineEdit_Vehicle_ID.setAlignment(Qt::AlignCenter);
    lineEdit_Requested_Energy.setFont(font_table2); lineEdit_Requested_Energy.setReadOnly(true); lineEdit_Requested_Energy.setAlignment(Qt::AlignCenter);
    lineEdit_Delivered_Energy.setFont(font_table2); lineEdit_Delivered_Energy.setReadOnly(true); lineEdit_Delivered_Energy.setAlignment(Qt::AlignCenter);
    lineEdit_Protocol.setFont(font_table2); lineEdit_Protocol.setReadOnly(true); lineEdit_Protocol.setAlignment(Qt::AlignCenter);

    label_40.setFont(font_title); label_40.setAlignment(Qt::AlignCenter);
    label_41.setFont(font_table);
    label_42.setFont(font_table);
    label_43.setFont(font_table);
    label_44.setFont(font_table);
    label_45.setFont(font_table);
    label_46.setFont(font_table);
    label_47.setFont(font_table);
    label_48.setFont(font_table);
    lineEdit_Mode.setFont(font_table2); lineEdit_Mode.setReadOnly(true);
    lineEdit_VARh.setFont(font_table2); lineEdit_VARh.setReadOnly(true);
    lineEdit_I_RMS.setFont(font_table2); lineEdit_I_RMS.setReadOnly(true);
    lineEdit_V_RMS.setFont(font_table2); lineEdit_V_RMS.setReadOnly(true);
    lineEdit_KW.setFont(font_table2); lineEdit_KW.setReadOnly(true);
    lineEdit_Reactive.setFont(font_table2); lineEdit_Reactive.setReadOnly(true);
    lineEdit_Active.setFont(font_table2); lineEdit_Active.setReadOnly(true);
    lineEdit_Apparent.setFont(font_table2); lineEdit_Apparent.setReadOnly(true);

    label_60.setFont(font_title); label_60.setAlignment(Qt::AlignCenter);
    label_61.setFont(font_table); label_61.setAlignment(Qt::AlignCenter);
    lineEdit_Card_UID.setFont(font_table2); lineEdit_Card_UID.setReadOnly(true); lineEdit_Card_UID.setAlignment(Qt::AlignCenter);

}

