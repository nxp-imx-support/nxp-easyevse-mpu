/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/

#ifndef TOP_WIDGET_H
#define TOP_WIDGET_H

#include <QObject>
#include <QWidget>
#include <QVBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QTimer>
#include <QSizePolicy>
#include <QMessageBox>

class top_widget : public QWidget
{
    Q_OBJECT
public:
    explicit top_widget(QWidget *parent = nullptr);
    ~top_widget();

    void setup_widget_main();

    QTimer timer;
    uint count;

    QFrame frame1;
    QFrame frame2;
    QFrame frame3;
    QFrame frame4;
    QFrame frame5;
    QFrame frame6;

    QVBoxLayout layout_main_v;
    QHBoxLayout layout_main_h;
    QHBoxLayout layout_main_menu;
    QHBoxLayout layout_main_menu_h1;
    QHBoxLayout layout_main_menu_h2;
    QHBoxLayout layout_main_menu_h3;
    QPushButton cloud_icon;

    QHBoxLayout layout_main_evse_ev;
    QVBoxLayout layout_main_evse_ev_v1;
    QVBoxLayout layout_main_evse_ev_v2;
    QHBoxLayout layout_main_evse_ev_h1;
    QHBoxLayout layout_main_evse_ev_h2;
    QHBoxLayout layout_main_evse_ev_h3;
    QGridLayout layout_main_evse_ev_g1;
    QGridLayout layout_main_evse_ev_g2;
    QHBoxLayout layout_main_bottom;
    QHBoxLayout layout_main_meter;
    QGridLayout layout_main_meter_g1;
    QGridLayout layout_main_meter_g2;
    QGridLayout layout_main_meter_g3;
    QVBoxLayout layout_main_control;
    QHBoxLayout layout_main_control_h;
    QVBoxLayout layout_main_control_v1;

    QLabel label_EVSE_ID; QLineEdit lineEdit_EVSE_ID;
    QLabel label_Charge_State; QLineEdit lineEdit_Charge_State;
    QPushButton Card_UID_icon; QLineEdit lineEdit_Card_UID;

    QPushButton evse_icon;
    QProgressBar pb;
    QPushButton ev_icon;
    QPushButton meter_icon;
    QPushButton finger_icon;

    QLabel energy_mode;
    QString energy_mode_flag;
    QString energy_mode_flag_old;
    bool forced_grid_pwr_limit;
    bool isPausing, reqPause;

    QLabel label_Auth_State; QLineEdit lineEdit_Auth_State;
    QLabel label_Power_Rate; QLineEdit lineEdit_Power_Rate;
    QLabel label_Grid_Limit; QLineEdit lineEdit_Grid_Limit;
    QLabel label_Temperature; QLineEdit lineEdit_Temperature;
    QLabel label_Charge_Current; QLineEdit lineEdit_Charge_Current;

    QLabel label_Vehicle_ID; QLineEdit lineEdit_Vehicle_ID;
    QLabel label_Requested_Energy; QLineEdit lineEdit_Requested_Energy;
    QLabel label_Delivered_Energy; QLineEdit lineEdit_Delivered_Energy;
    QLabel label_Mode; QLineEdit lineEdit_Mode;
    QLabel label_Protocol; QLineEdit lineEdit_Protocol;

    QLabel label_VARh; QLineEdit lineEdit_VARh;
    QLabel label_I_RMS; QLineEdit lineEdit_I_RMS;
    QLabel label_V_RMS; QLineEdit lineEdit_V_RMS;
    QLabel label_KW; QLineEdit lineEdit_KW;
    QLabel label_Reactive; QLineEdit lineEdit_Reactive;
    QLabel label_Active; QLineEdit lineEdit_Active;
    QLabel label_Apparent; QLineEdit lineEdit_Apparent;

    QLabel label_Remaining_Time; QLineEdit lineEdit_Remaining_Time;
    QLabel label_Elapsed_Time; QLineEdit lineEdit_Elapsed_Time;
    QLabel label_Charge_Cost; QLineEdit lineEdit_Charge_Cost;

    QLabel label_Transferred; QLineEdit lineEdit_Transferred;
    QLabel label_DisChg_V; QLineEdit lineEdit_DisChg_V;
    QLabel label_DisChg_I; QLineEdit lineEdit_DisChg_I;

    QPushButton btn_pause_resume;

    QLineEdit text_license;
    QLineEdit text_debug;

  signals:

  public slots:
    void onTimeout();
    void on_PushButton_Cloud_Icon_clicked();
    void on_PushButton_Pause_Resume_clicked();

  protected:
    void resizeEvent(QResizeEvent *event) override;
};

#endif // TOP_WIDGET_H
