/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/

#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <iostream>
#include <QCoreApplication>

/* Set some graphical elements when the application starts */
void MainWindow::StartupScreen()
{
    ui->stackedWidget->setCurrentIndex(0);
    setWindowTitle("Menu");
}

/* The application  */
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    StartupScreen();
}

MainWindow::~MainWindow()
{
    delete ui;
}

/* Events from the interaction with the interace */

void MainWindow::on_button_metrology_clicked()
{
    ui->stackedWidget->setCurrentIndex(1);
}

void MainWindow::on_button_nfc_card_clicked()
{
    ui->stackedWidget->setCurrentIndex(2);
}

void MainWindow::on_button_car_battery_clicked()
{
    ui->stackedWidget->setCurrentIndex(3);
}

void MainWindow::on_button_evse_status_clicked()
{
    ui->stackedWidget->setCurrentIndex(4);
}

void MainWindow::on_button_back_1_clicked()
{
    ui->stackedWidget->setCurrentIndex(0);
}

void MainWindow::on_button_back_2_clicked()
{
    ui->stackedWidget->setCurrentIndex(0);
}

void MainWindow::on_button_back_3_clicked()
{
    ui->stackedWidget->setCurrentIndex(0);
}

void MainWindow::on_button_back_4_clicked()
{
    ui->stackedWidget->setCurrentIndex(0);
}
