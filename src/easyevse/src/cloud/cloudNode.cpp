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
#include "interfaces/msg/stack_data.hpp"
#include "interfaces/msg/meter_data.hpp"

extern "C" {
  #include "easyevse/utils.h"
  #include "easyevse/cloud_api.h"
}

using namespace std::chrono_literals;
using namespace std;

using std::placeholders::_1;

class CloudNode : public rclcpp::Node
{
public:
  CloudNode()
  : Node("cloud_node")
  {
    publisher_ = this->create_publisher<interfaces::msg::CloudData>("cloud_data", 10);

    general_data_subscription_ = this->create_subscription<interfaces::msg::GeneralData>(
      "general_data", 10, std::bind(&CloudNode::general_data_callback, this, _1));

    stack_data_subscription_ = this->create_subscription<interfaces::msg::StackData>(
      "stack_data", 10, std::bind(&CloudNode::stack_data_callback, this, _1));

    meter_data_subscription_ = this->create_subscription<interfaces::msg::MeterData>(
      "meter_data", 10, std::bind(&CloudNode::meter_data_callback, this, _1));
  }

  void init_cloud_data()
  {
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
    stack_data.energy_transfer_dir = 0;
    stack_data.present_soc = 0;
    stack_data.ev_present_voltage_dis = 0.0;
    stack_data.ev_present_current_dis = 0.0;
    stack_data.is_pausing = false;

    meter_data.current = 1.1;
    meter_data.voltage = 2.2;
    meter_data.power = 3.3;
  }

  void sendReportedProperties(const volatile struct cloud_properties *reported_properties) 
  {    
    cloud_data.grid_pwr_lim = reported_properties->grid_pwr_lim;
    cloud_data.tariff_cost = reported_properties->tariff_cost;
    cloud_data.tariff_rate = reported_properties->tariff_rate;

    //RCLCPP_INFO(this->get_logger(), "Publishing grid power limit: '%.2f'", cloud_data.grid_pwr_lim);
    //RCLCPP_INFO(this->get_logger(), "Publishing tariff cost: '%.2f'", cloud_data.tariff_cost);
    //RCLCPP_INFO(this->get_logger(), "Publishing tariff rate: '%.2f'", cloud_data.tariff_rate);
    
    publisher_->publish(cloud_data);
  }

  void sendStopReq(const volatile bool *reported_stop) 
  {    
    cloud_data.grid_stop_req = *reported_stop;

    //RCLCPP_INFO(this->get_logger(), "Publishing grid stop request: '%d'", cloud_data.grid_stop_req);
    
    publisher_->publish(cloud_data);
    last = std::chrono::steady_clock::now();
  }

  char* prepare_data()
  {
    cJSON *telemetry_data = NULL, *location_data = NULL;
    char *telemetry = NULL; 

    telemetry_data = cJSON_CreateObject();
    location_data = cJSON_CreateObject();
    
    cJSON_AddStringToObject(telemetry_data, "EVSEID", (general_data.evse_id).c_str());
    cJSON_AddStringToObject(telemetry_data, "FirmwareVersion", (general_data.fw_vers).c_str());
    cJSON_AddNumberToObject(location_data, "lon", general_data.lon);
    cJSON_AddNumberToObject(location_data, "lat", general_data.lat);
    cJSON_AddNumberToObject(location_data, "alt", general_data.alt);
    cJSON_AddItemToObject(telemetry_data, "EVSELocation", location_data);
    cJSON_AddNumberToObject(telemetry_data, "EVSELimit", general_data.evse_rating);
    cJSON_AddNumberToObject(telemetry_data, "Temperature", general_data.temperature);

    cJSON_AddStringToObject(telemetry_data, "VehicleID", (stack_data.evcc_id).c_str());
    cJSON_AddStringToObject(telemetry_data, "AuthenticationState", (stack_data.vehicle_auth).c_str());
    cJSON_AddNumberToObject(telemetry_data, "EnergyRequested", stack_data.energy_requested);
    cJSON_AddNumberToObject(telemetry_data, "ChargeRate", stack_data.chg_rate);
    cJSON_AddStringToObject(telemetry_data, "TimeRemaining", (stack_data.chg_remaining_time).c_str());
    cJSON_AddStringToObject(telemetry_data, "ElapsedTime", (stack_data.chg_elapsed_time).c_str());
    cJSON_AddNumberToObject(telemetry_data, "ChargeCost", stack_data.chg_cost);
    cJSON_AddNumberToObject(telemetry_data, "EnergyDelivered", stack_data.energy_delivered);
    cJSON_AddStringToObject(telemetry_data, "ChargeStatus", (stack_data.chg_state).c_str());
    cJSON_AddNumberToObject(telemetry_data, "IsCharging", stack_data.charging);
    cJSON_AddStringToObject(telemetry_data, "ChargeDirection", stack_data.energy_transfer_dir ? "Discharge" : "Charge");
    cJSON_AddStringToObject(telemetry_data, "Protocol", stack_data.protocol.c_str());

    cJSON_AddNumberToObject(telemetry_data, "irms", meter_data.current);
    cJSON_AddNumberToObject(telemetry_data, "vrms", meter_data.voltage);
    cJSON_AddNumberToObject(telemetry_data, "kw", meter_data.power);

    telemetry = cJSON_PrintUnformatted(telemetry_data);

    cJSON_Delete(telemetry_data);

    return telemetry;
  }

  interfaces::msg::CloudData cloud_data;
  std::chrono::time_point<std::chrono::steady_clock> last;
private:
  void cloud_telemetry_callback()
  {
    IOTHUB_MESSAGE_HANDLE message_handle;
    char *telemetry_data = prepare_data();
    //(void)printf("\r\nSending message to IoTHub\r\nMessage: %s\r\n", telemetry_data);
    message_handle = IoTHubMessage_CreateFromString(telemetry_data);
    IoTHubDeviceClient_SendEventAsync(device_handle, message_handle, send_confirm_callback, NULL);
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
    cloud_telemetry_callback();
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
    stack_data.energy_transfer_dir = msg->energy_transfer_dir;
    cloud_telemetry_callback();
  }

  void meter_data_callback(const interfaces::msg::MeterData::SharedPtr msg)
  {
    meter_data.current = msg->current;
    meter_data.voltage = msg->voltage;
    meter_data.power = msg->power;
    cloud_telemetry_callback();
  }

  interfaces::msg::GeneralData general_data;
  interfaces::msg::StackData stack_data;
  interfaces::msg::MeterData meter_data;
  rclcpp::Publisher<interfaces::msg::CloudData>::SharedPtr publisher_;
  rclcpp::Subscription<interfaces::msg::GeneralData>::SharedPtr general_data_subscription_;
  rclcpp::Subscription<interfaces::msg::MeterData>::SharedPtr meter_data_subscription_;
  rclcpp::Subscription<interfaces::msg::StackData>::SharedPtr stack_data_subscription_;
};

std::shared_ptr<CloudNode> node;

extern "C" void C_sendReportedProperties(const volatile struct cloud_properties *reported_properties) 
{
  node->sendReportedProperties(reported_properties);
}

extern "C" void C_sendStopReq(const bool *reported_stop) 
{
  node->sendStopReq(reported_stop);
}

int main(int argc, char * argv[])
{
  
  std::chrono::duration<double> timediff;
  int retCode;
  bool clear_stop_req = false;
  rclcpp::init(argc, argv);

  rclcpp::executors::SingleThreadedExecutor executor;

  node = std::make_shared<CloudNode>();

  node->init_cloud_data();

  retCode = InitCloud();
  if (retCode == -1)
  {
      CloudDeinit();
      return retCode;
  }

  executor.add_node(node);

  while(1)
  {
    // Spin every 2 sec
    executor.spin_once(2 * 1000000000ns);
    if(node->cloud_data.grid_stop_req == true)
    {
      timediff = std::chrono::steady_clock::now() - node->last;
      if(timediff.count() > 2)
      {
        node->sendStopReq(&clear_stop_req);
      }
    }
  }

  rclcpp::shutdown();

  CloudDeinit();
  
  return 0;
}
