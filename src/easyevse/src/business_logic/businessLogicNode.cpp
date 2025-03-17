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
#include "interfaces/msg/general_data.hpp"
#include "easyevse/typedefs.h"

using namespace std::chrono_literals;
using namespace std;

using std::placeholders::_1;

class BusinessLogicNode : public rclcpp::Node
{
public:
  BusinessLogicNode()
  : Node("business_logic")
  {
    publisher_ = this->create_publisher<interfaces::msg::GeneralData>("general_data", 10);
  }

  void init_general_data() 
  {
    general_data.fw_vers = "v1.0";
    general_data.lat = 45.029858820811924;
    general_data.lon = 25.837845529477256;
    general_data.alt = 314.96;
    general_data.temperature = 30;
    general_data.evse_id = "NXP@EASYEVSE";
    general_data.evse_rating = MAX_EVSE_CURRENT;
    RCLCPP_INFO(this->get_logger(), "Initialised general charger data\n");
    publisher_->publish(general_data);
  }

  void temperature_sim()
  {
    general_data.temperature++;
    if(general_data.temperature > 40)
    {
      general_data.temperature = 30;
    }
    RCLCPP_INFO(this->get_logger(), "Publishing temperature: '%d'", general_data.temperature);
    publisher_->publish(general_data);

  }

private:
  interfaces::msg::GeneralData general_data;
  rclcpp::Publisher<interfaces::msg::GeneralData>::SharedPtr publisher_;
};

std::shared_ptr<BusinessLogicNode> node;

int main(int argc, char * argv[])
{
  rclcpp::init(argc, argv);

  rclcpp::executors::SingleThreadedExecutor executor;
  
  node = std::make_shared<BusinessLogicNode>();

  node->init_general_data();

  executor.add_node(node);

  while(1)
  {
    // Spin every 2 sec
    executor.spin_once(2 * 1000000000ns);
    node->temperature_sim();
  }
  rclcpp::shutdown();
  return 0;
}
