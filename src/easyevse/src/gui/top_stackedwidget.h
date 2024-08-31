/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/

#ifndef TOP_STACKEDWIDGET_H
#define TOP_STACKEDWIDGET_H

#include <QObject>
#include <QWidget>
#include <QStackedWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QTimer>

class top_stackedwidget : public QStackedWidget
{
    Q_OBJECT
public:
    explicit top_stackedwidget(QStackedWidget *parent = nullptr);
    ~top_stackedwidget();

    void setup_widget_main();
    void setup_widget_status();
    void setup_widget_battery();
    void setup_widget_meter();
    void setup_widget_nfc();

    void timer_update();

    QTimer timer;
    QWidget widget_main;
    QWidget widget_status;
    QWidget widget_battery;
    QWidget widget_meter;
    QWidget widget_nfc;
    QPushButton btn_status;
    QPushButton btn_battery;
    QPushButton btn_meter;
    QPushButton btn_nfc;
    QPushButton btn_back_1;
    QPushButton btn_back_2;
    QPushButton btn_back_3;
    QPushButton btn_back_4;

    QFont font_title;
    QFont font_table;
    QFont font_table2;
    QFont font_license;

    //main
    QGridLayout layout_main;
    QLineEdit text_license;

    //status
    QVBoxLayout layout_status_v;
    QHBoxLayout layout_status_h_1;
    QHBoxLayout layout_status_h_2;
    QGridLayout layout_status_g_1;
    QGridLayout layout_status_g_2;
    QLabel label_0;
    QLabel label_1;
    QLabel label_2;
    QLabel label_3;
    QLabel label_4;
    QLabel label_5;
    QLabel label_6;
    QLabel label_7;
    QLabel label_8;
    QLabel label_9;
    QLabel label_10;
    QLineEdit lineEdit_Charge_State;
    QLineEdit lineEdit_Power_Rate;
    QLineEdit lineEdit_Auth_State;
    QLineEdit lineEdit_Charge_Cost;
    QLineEdit lineEdit_Charge_Current;
    QLineEdit lineEdit_EVSE_ID;
    QLineEdit lineEdit_Grid_Limit;
    QLineEdit lineEdit_Temperature;
    QLineEdit lineEdit_Time2Charge;
    QLineEdit lineEdit_Elapsed_Time;

    //battery
    QVBoxLayout layout_battery_v;
    QHBoxLayout layout_battery_h;
    QGridLayout layout_battery_g;
    QLabel label_20;
    QLabel label_21;
    QLabel label_22;
    QLabel label_23;
    QLabel label_24;
    QLineEdit lineEdit_Vehicle_ID;
    QLineEdit lineEdit_Requested_Energy;
    QLineEdit lineEdit_Delivered_Energy;
    QLineEdit lineEdit_Protocol;
    QProgressBar pb;

    //meter
    QVBoxLayout layout_meter_v;
    QHBoxLayout layout_meter_h_1;
    QHBoxLayout layout_meter_h_2;
    QGridLayout layout_meter_g_1;
    QGridLayout layout_meter_g_2;
    QLabel label_40;
    QLabel label_41;
    QLabel label_42;
    QLabel label_43;
    QLabel label_44;
    QLabel label_45;
    QLabel label_46;
    QLabel label_47;
    QLabel label_48;
    QLineEdit lineEdit_Mode;
    QLineEdit lineEdit_VARh;
    QLineEdit lineEdit_I_RMS;
    QLineEdit lineEdit_V_RMS;
    QLineEdit lineEdit_KW;
    QLineEdit lineEdit_Reactive;
    QLineEdit lineEdit_Active;
    QLineEdit lineEdit_Apparent;

    //nfc
    QVBoxLayout layout_nfc_v;
    QHBoxLayout layout_nfc_h;
    QGridLayout layout_nfc_g;
    QLabel label_60;
    QLabel label_61;
    QLineEdit lineEdit_Card_UID;
  signals:

  protected:
    void resizeEvent(QResizeEvent *event) override;
};

#endif // TOP_STACKEDWIDGET_H

