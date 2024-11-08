/**************************************************************************/
/* Copyright 2023-2024 NXP                                                */
/*                                                                        */
/* SPDX-License-Identifier: Apache-2.0                                    */
/**************************************************************************/


#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "top_widget.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    top_widget top_widget_inst;

};
#endif // MAINWINDOW_H
