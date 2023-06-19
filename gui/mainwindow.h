/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/


#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
extern "C"{
#include "../include/typedefs.h"
#include "../include/utils.h"
#include "../include/logger.h"
}

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class QLocalSocket;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void StartupScreen();
    void CreateSocketConnection();
    void SendIdentity();
    void ExtractData(QJsonObject);
    void UpdateInterface();
    void UpdateBattery(QString);
    QString PrepareJSONMessage();

private slots:
    void on_button_metrology_clicked();

    void on_button_evse_status_clicked();

    void on_button_car_battery_clicked();

    void on_button_nfc_card_clicked();

    void on_button_back_1_clicked();

    void on_button_back_2_clicked();

    void on_button_back_3_clicked();

    void on_button_back_4_clicked();

    void on_horizontalSlider_valueChanged(int value);

private:
    Ui::MainWindow *ui;
    QLocalSocket *mSocket;

    // variables used for storing data received from server
    int type;
    double chg_cost;
    double evse_rating;
    double temperature;
    QString vehicle_auth;
    QString chg_time;
    QString chgsta;
    double current;
    double power;
    double voltage;
    QString card_id;
    double battery_value;
    double grid_pwr_lim;
    QString evse_id;

};
#endif // MAINWINDOW_H