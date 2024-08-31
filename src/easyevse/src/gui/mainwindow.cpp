/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/

#include "mainwindow.h"

/* The application  */
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("EasyEVSE");
    this->setCentralWidget(&stacked_widget);
}

MainWindow::~MainWindow()
{

}
