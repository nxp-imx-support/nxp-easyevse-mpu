/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/


#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void StartupScreen();
    void UpdateBattery(QString);

private slots:
    void on_button_metrology_clicked();

    void on_button_evse_status_clicked();

    void on_button_car_battery_clicked();

    void on_button_nfc_card_clicked();

    void on_button_back_1_clicked();

    void on_button_back_2_clicked();

    void on_button_back_3_clicked();

    void on_button_back_4_clicked();

public:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
