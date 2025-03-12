/*
 * Copyright 2016 Open Source Robotics Foundation, Inc.
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Informed by the ROS publisher/subscriber tutorials at
 * https://docs.ros.org/en/humble/Tutorials/Beginner-Client-Libraries/Writing-A-Simple-Cpp-Publisher-And-Subscriber.html
 */

#include <chrono>
#include <memory>

#include "rclcpp/rclcpp.hpp"
#include "interfaces/msg/cloud_data.hpp"
#include "interfaces/msg/general_data.hpp"
#include "interfaces/msg/gui_data.hpp"
#include "interfaces/msg/meter_data.hpp"
#include "interfaces/msg/nfc_data.hpp"
#include "interfaces/msg/stack_data.hpp"
#include "mainwindow.h"
#include <QApplication>


using namespace std::chrono_literals;

using std::placeholders::_1;

MainWindow *w;  

class GUINode : public rclcpp::Node
{
public:
  GUINode()
  : Node("gui_node")
  {
    publisher_ = this->create_publisher<interfaces::msg::GuiData>("gui_data", 10);
    timer_ = this->create_wall_timer(
      1000ms, std::bind(&GUINode::timer_callback, this));

    cloud_data_subscription_ = this->create_subscription<interfaces::msg::CloudData>(
      "cloud_data", 10, std::bind(&GUINode::cloud_data_callback, this, _1));

    general_data_subscription_ = this->create_subscription<interfaces::msg::GeneralData>(
      "general_data", 10, std::bind(&GUINode::general_data_callback, this, _1));

    stack_data_subscription_ = this->create_subscription<interfaces::msg::StackData>(
      "stack_data", 10, std::bind(&GUINode::stack_data_callback, this, _1));

    meter_data_subscription_ = this->create_subscription<interfaces::msg::MeterData>(
      "meter_data", 10, std::bind(&GUINode::meter_data_callback, this, _1));

    nfc_data_subscription_ = this->create_subscription<interfaces::msg::NfcData>(
      "nfc_data", 10, std::bind(&GUINode::nfc_data_callback, this, _1));
  }

  void init_gui_data()
  {
    gui_data.user_stop_req = false;
    gui_data.user_force_req = false;
    gui_data.user_pause_req = false;
    gui_data.user_force_pwr = 0;
    gui_data.user_force_cost = 0;
    gui_data.user_force_rate = 0;
    
    cloud_data.grid_pwr_lim = 32.0;
    cloud_data.tariff_cost = 0.0;
    cloud_data.tariff_rate = 0.0;
    cloud_data.grid_stop_req = false;

    general_data.fw_vers = "0";
    general_data.lat = 0.0;
    general_data.lon = 0.0;
    general_data.alt = 0.0;
    general_data.temperature = 40;
    general_data.evse_id = "0";
    general_data.evse_rating = 0;

    stack_data.evcc_id = "0";
    stack_data.vehicle_auth = "fail";
    stack_data.energy_requested = 0;
    stack_data.chg_rate = 0;
    stack_data.chg_cost = 0;
    stack_data.chg_elapsed_time = "00H:00M:00S";
    stack_data.chg_remaining_time = "N/A";
    stack_data.chg_state = "A";
    stack_data.energy_delivered = 0.0;
    stack_data.protocol = "none";
    stack_data.charging = false;
    stack_data.energy_transfer_dir = -1;
    stack_data.present_soc = 0;
    stack_data.ev_present_voltage_dis = 0.0;
    stack_data.ev_present_current_dis = 0.0;
    stack_data.is_pausing = false;

    meter_data.current = 1.1;
    meter_data.voltage = 2.2;
    meter_data.power = 3.3;

    nfc_data.nfc_id = "0";
  }

  void sendStopReq(const volatile bool *reported_stop) 
  {    
    gui_data.user_stop_req = *reported_stop;

    //RCLCPP_INFO(this->get_logger(), "Publishing user stop request: '%d'", cloud_data.grid_stop_req);
    
    publisher_->publish(gui_data);
    last = std::chrono::steady_clock::now();
  }

  interfaces::msg::GuiData gui_data;
  std::chrono::time_point<std::chrono::steady_clock> last;

private:
  void timer_callback()
  {
    if(gui_data.user_force_req != w->top_widget_inst.forced_grid_pwr_limit)
    {
      if(w->top_widget_inst.forced_grid_pwr_limit)
      {
        gui_data.user_force_req = true;
        gui_data.user_force_pwr = 9;
        gui_data.user_force_cost = 3;
        gui_data.user_force_rate = 4;
      }
      else
      {
        gui_data.user_force_req = false;
        gui_data.user_force_pwr = 0;
        gui_data.user_force_cost = 0;
        gui_data.user_force_rate = 0;
      }
      publisher_->publish(gui_data);
      QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Grid_Limit, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(gui_data.user_force_pwr)));
    }

    if(w->top_widget_inst.isPausing)
    {
      w->top_widget_inst.btn_pause_resume.setText("PAUSED");
      QMetaObject::invokeMethod(&w->top_widget_inst.timer, "stop", Qt::QueuedConnection, QGenericArgument());
      gui_data.user_pause_req = false;
      publisher_->publish(gui_data);
    }
    else
    {
      w->top_widget_inst.btn_pause_resume.setText("PAUSE");
      QMetaObject::invokeMethod(&w->top_widget_inst.timer, "start", Qt::QueuedConnection, 300);
      if(w->top_widget_inst.reqPause)
      {
        gui_data.user_pause_req = true;
        w->top_widget_inst.reqPause = false;
        publisher_->publish(gui_data);
      }
    }
  }

  void general_data_callback(const interfaces::msg::GeneralData::SharedPtr msg)
  {
    general_data.fw_vers = msg->fw_vers;
    general_data.lat = msg->lat;
    general_data.lon = msg->lon;
    general_data.alt = msg->alt;
    general_data.temperature = msg->temperature;
    general_data.evse_id = msg->evse_id;
    general_data.evse_rating = msg->evse_rating;

    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Power_Rate, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->evse_rating)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_EVSE_ID, "setText", Qt::QueuedConnection, Q_ARG(QString, msg->evse_id.c_str()));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Temperature, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->temperature)));
  }

  void stack_data_callback(const interfaces::msg::StackData::SharedPtr msg)
  {
    stack_data.evcc_id = msg->evcc_id;
    stack_data.vehicle_auth = msg->vehicle_auth;
    stack_data.energy_requested = msg->energy_requested;
    stack_data.chg_rate = msg->chg_rate;
    stack_data.chg_cost = msg->chg_cost;
    stack_data.chg_elapsed_time = msg->chg_elapsed_time;
    stack_data.chg_remaining_time = msg->chg_remaining_time;
    stack_data.chg_state = msg->chg_state;
    stack_data.energy_delivered = msg->energy_delivered;
    stack_data.protocol = msg->protocol;
    stack_data.charging = msg->charging;
    stack_data.is_pausing = msg->is_pausing;

    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Vehicle_ID, "setText", Qt::QueuedConnection, Q_ARG(QString, msg->evcc_id.c_str()));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Auth_State, "setText", Qt::QueuedConnection, Q_ARG(QString, msg->vehicle_auth.c_str()));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Requested_Energy, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->energy_requested/1000.0)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Charge_Current, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->chg_rate)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Charge_Cost, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->chg_cost)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Elapsed_Time, "setText", Qt::QueuedConnection, Q_ARG(QString, msg->chg_elapsed_time.c_str()));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Remaining_Time, "setText", Qt::QueuedConnection, Q_ARG(QString, msg->chg_remaining_time.c_str()));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Mode, "setText", Qt::QueuedConnection, Q_ARG(QString, msg->chg_state.c_str()));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Delivered_Energy, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->energy_delivered/1000.0)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Protocol, "setText", Qt::QueuedConnection, Q_ARG(QString, msg->protocol.c_str()));
    if(msg->charging) {
	if(msg->energy_transfer_dir == 0)
            w->top_widget_inst.energy_mode_flag = "charging";
	else if(msg->energy_transfer_dir == 1)
	    w->top_widget_inst.energy_mode_flag = "discharging";
	else
	    w->top_widget_inst.energy_mode_flag = "unknown";
    } else {
        w->top_widget_inst.energy_mode_flag = "unknown";
    }

    QMetaObject::invokeMethod(&w->top_widget_inst.pb, "setValue", Qt::QueuedConnection, Q_ARG(int, msg->present_soc));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_DisChg_V, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->ev_present_voltage_dis)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_DisChg_I, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->ev_present_current_dis)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Transferred, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->energy_delivered/1000.0)));

    w->top_widget_inst.isPausing = stack_data.is_pausing;
  }

  void meter_data_callback(const interfaces::msg::MeterData::SharedPtr msg)
  {
    meter_data.current = msg->current;
    meter_data.voltage = msg->voltage;
    meter_data.power = msg->power;

    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_VARh, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(0)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Reactive, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(0)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Active, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->power/1000.0)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Apparent, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->power/1000.0)));

    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_I_RMS, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->current)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_V_RMS, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->voltage)));
    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_KW, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->power/1000.0)));
  }

  void nfc_data_callback(const interfaces::msg::NfcData::SharedPtr msg)
  {
    nfc_data.nfc_id = msg->nfc_id;

    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Card_UID, "setText", Qt::QueuedConnection, Q_ARG(QString, msg->nfc_id.c_str()));
  }

  void cloud_data_callback(const interfaces::msg::CloudData::SharedPtr msg)
  { 
    if(gui_data.user_force_req)
	    return;

    cloud_data.grid_pwr_lim = msg->grid_pwr_lim;
    cloud_data.tariff_cost = msg->tariff_cost;
    cloud_data.tariff_rate = msg->tariff_rate;
    cloud_data.grid_stop_req = msg->grid_stop_req;

    QMetaObject::invokeMethod(&w->top_widget_inst.lineEdit_Grid_Limit, "setText", Qt::QueuedConnection, Q_ARG(QString, QString::number(msg->grid_pwr_lim)));
  }

  interfaces::msg::CloudData cloud_data;
  interfaces::msg::GeneralData general_data;
  interfaces::msg::MeterData meter_data;
  interfaces::msg::NfcData nfc_data;
  interfaces::msg::StackData stack_data;

  rclcpp::TimerBase::SharedPtr timer_;

  rclcpp::Subscription<interfaces::msg::CloudData>::SharedPtr cloud_data_subscription_;
  rclcpp::Subscription<interfaces::msg::GeneralData>::SharedPtr general_data_subscription_;
  rclcpp::Subscription<interfaces::msg::MeterData>::SharedPtr meter_data_subscription_;
  rclcpp::Subscription<interfaces::msg::NfcData>::SharedPtr nfc_data_subscription_;
  rclcpp::Subscription<interfaces::msg::StackData>::SharedPtr stack_data_subscription_;
  
  rclcpp::Publisher<interfaces::msg::GuiData>::SharedPtr publisher_;
};

std::shared_ptr<GUINode> node;

void ros_run() {

  std::chrono::duration<double> timediff;
  int retCode;
  bool clear_stop_req = false;

  rclcpp::executors::SingleThreadedExecutor executor;

  executor.add_node(node);

  while(1)
  {
    // Refresh every second
    executor.spin_once(1000000000ns);
    if(node->gui_data.user_stop_req == true)
    {
      timediff = std::chrono::steady_clock::now() - node->last;
      if(timediff.count() > 2)
      {
        node->sendStopReq(&clear_stop_req);
      }
    }
  }
}



int main(int argc, char * argv[])
{
  QApplication app(argc, argv); 
  w = new MainWindow; 
  rclcpp::init(argc, argv);

  node = std::make_shared<GUINode>();
  node->init_gui_data();

  std::thread ros_thread(ros_run);
  w->showFullScreen();
  app.exec();
  rclcpp::shutdown();
  delete w;
  return 0;
}
