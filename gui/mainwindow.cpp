/**************************************************************************/
/* Copyright 2023 NXP                                                     */
/* NXP Confidential. This software is owned or controlled by NXP and may  */
/* only be used strictly in accordance with the applicable license terms  */
/* found at https://www.nxp.com/docs/en/disclaimer/LA_OPT_NXP_SW.html     */
/**************************************************************************/


#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QLocalSocket>
#include <iostream>
#include <QJsonParseError>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QCoreApplication>

// GUI identity variable defined only in GUI app
EndPoint_t identity = GUI;

// GUI local socket descriptor
int endpointFd;

// GUI identity variable defined only in mainwindow.cpp
LoggingLevel_t logLevel = ALL;

// Log file descriptor
// default logging output is stdout
int logFileDesc = STDOUT_FD;

int battery_level;


/* Set some graphical elements when the application starts */
void MainWindow::StartupScreen()
{
    ui->stackedWidget->setCurrentIndex(0);
    ui->horizontalSlider->setMinimum(0);
    ui->horizontalSlider->setMaximum(100);
    ui->horizontalSlider->setValue(100);
    ui->horizontalSlider->setTickInterval(1);
    setWindowTitle("Menu");
}


/* Connect to server through local socket */
void MainWindow::CreateSocketConnection()
{
    mSocket = new QLocalSocket(this);

    mSocket->connectToServer(QCoreApplication::applicationDirPath() + "/server.socket");
    if (mSocket->waitForConnected(2000))
        LogEvent(identity, SOCKET_CONNECTION_OK, NULL, logFileDesc);
    else
        LogEvent(identity, SOCKET_CONNECTION_FAIL, NULL , logFileDesc);
}


/* Send identity to the server */
void MainWindow::SendIdentity()
{
    char buffer[16];
    int retCode;

    sprintf(buffer, "%d", identity);
    retCode = mSocket->write(buffer);

    if (retCode == -1)
        LogEvent(identity, SEND_IDENTITY_FAIL, NULL, logFileDesc);
    else
        LogEvent(identity, SEND_IDENTITY_OK, NULL, logFileDesc);
}


/* Check charging state and increase battery if the case;
   As the server sends messages to the gui each x seconds,
   the battery incrementation will seem continuous */
void MainWindow::UpdateBattery(QString chgsta)
{
    if (chgsta == "C"){
        this->ui->radioButton->setChecked(true);
        if (battery_level < 100)
            battery_level++;
    }
    else{
        if (battery_level != 0)
            battery_level = 0;
        this->ui->radioButton->setChecked(false);
    }
    // update battery level in the interface
    this->ui->horizontalSlider->setValue(battery_level);
}


/* Extract each element from the received json message */
void MainWindow::ExtractData(QJsonObject jsonData_server)
{
    chg_cost = jsonData_server.value("chg_cost").toDouble();
    evse_rating = jsonData_server.value("evse_rating").toDouble();
    temperature = jsonData_server.value("temperature").toDouble();
    vehicle_auth = jsonData_server.value("vehicle_auth").toString();
    chg_time = jsonData_server.value("chg_time").toString();
    chgsta = jsonData_server.value("chgsta").toString();
    current = jsonData_server.value("current").toDouble();
    power = jsonData_server.value("power").toDouble();
    voltage = jsonData_server.value("voltage").toDouble();
    card_id = jsonData_server.value("card_id").toString();
    battery_value = jsonData_server.value("battery_value").toDouble();
    grid_pwr_lim = jsonData_server.value("grid_pwr_lim").toDouble();
    evse_id = jsonData_server.value("evse_id").toString();
}


/* Update each field from the the graphical interface  */
void MainWindow::UpdateInterface()
{
    // update meter menu
    this->ui->lineEdit_1->setText(QString("%2").arg(chgsta));
    this->ui->lineEdit_2->setText(QString("%2").arg(0));
    this->ui->lineEdit_3->setText(QString("%2").arg(current));
    this->ui->lineEdit_4->setText(QString("%2").arg(voltage));
    this->ui->lineEdit_5->setText(QString("%2").arg(power));
    this->ui->lineEdit_6->setText(QString("%2").arg(0));
    this->ui->lineEdit_7->setText(QString("%2").arg(power));
    this->ui->lineEdit_8->setText(QString("%2").arg(power));

    // update status menu
    this->ui->lineEdit_9->setText(QString("%2").arg(evse_rating));
    this->ui->lineEdit_10->setText(QString("%2").arg(vehicle_auth));
    this->ui->lineEdit_11->setText(QString("%2").arg(chg_cost));
    this->ui->lineEdit_12->setText(QString("%2").arg(evse_id));
    this->ui->lineEdit_13->setText(QString("%2").arg(grid_pwr_lim));
    this->ui->lineEdit_14->setText(QString("%2").arg(temperature));
    this->ui->lineEdit_15->setText(QString("%2").arg(chg_time));

    // update NFC menu
    this->ui->lineEdit->setText(QString("%2").arg(card_id));

    // update car battery menu
    this->ui->lineEdit_32->setText(QString("%2").arg(card_id));
    UpdateBattery(chgsta);
}


/* Create json message whith the structure expected by the server */
QString MainWindow::PrepareJSONMessage()
{
    QJsonObject json_data;
    QJsonObject json_gui_data;
    QJsonDocument send_msg;

    json_gui_data.insert("battery_value", QJsonValue::fromVariant(battery_level));
    json_data.insert("Client", QJsonValue::fromVariant(EndPoint_t::GUI));
    json_data.insert("Data", json_gui_data);
    send_msg.setObject(json_data);

    if (send_msg.isEmpty())
        LogEvent(identity, JSON_STRUCTURE_PREP_FAIL, NULL, logFileDesc);
    else
        LogEvent(identity, JSON_PREPARE_OK, NULL, logFileDesc);

    return (QString)send_msg.toJson();
}


/* The application  */
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    PrepareLoggingEnv(identity);
    StartupScreen();
    CreateSocketConnection();
    SendIdentity();

    /* signal and slot mechanism - used for reading  data when signal is received */
    connect(mSocket, &QLocalSocket::readyRead, [&](){

        QString read_msg = mSocket->readAll();
        QByteArray bytes = read_msg.toUtf8();
        if ( bytes.isEmpty() )
            LogEvent(identity, READ_FAIL, NULL, logFileDesc);
        else {
            QJsonParseError jsonError;
            QJsonDocument data = QJsonDocument::fromJson( bytes, &jsonError );
            if( jsonError.error != QJsonParseError::NoError )
            {
                LogEvent(identity, JSON_PARSE_FAIL, NULL, logFileDesc);
                return ;
            }
            // there is not LogEvent for JSON_PARSE_OK because the log file would increase very fast


            if( data.isObject() )
            {
                QJsonObject jsonObj = data.object();
                QJsonObject jsonData_server;
                type = jsonObj.value("Type").toInt();
                jsonData_server = jsonObj.value("Data").toObject();

                /* type = 1 => update data in interface;
                 * type = 0 => send battery value to server */
                if (type == 1)
                {
                    ExtractData(jsonData_server);
                    UpdateInterface();
                }
                else if (type == 0)
                {
                    QString write_msg = PrepareJSONMessage();
                    int retCode = mSocket->write(write_msg.toLocal8Bit());
                    if (retCode == -1)
                        LogEvent(identity, SEND_MESSAGE_FAIL, NULL, logFileDesc);
                    // there is not LogEvent for SEND_MESSAGE_OK the log file would increase very fast
                }
            }
        }

    });
}


MainWindow::~MainWindow()
{
    delete ui;
    delete mSocket;
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


void MainWindow::on_horizontalSlider_valueChanged(int value)
{
    ui->lineEdit_33->setText(QString("%2").arg(value));
    battery_level = value;
}