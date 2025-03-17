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
#include "interfaces/msg/nfc_data.hpp"

extern "C" {
  #include "easyevse/nfc_api.h"
}

using namespace std::chrono_literals;
using namespace std;

// Log file descriptor
// default logging output is stdout
volatile int logFileDesc = STDOUT_FD;

// Logging level
LoggingLevel_t logLevel = ALL;

// NFC identity variable defined only in nfc_app.c
EndPoint_t identity = NFC;

extern "C" void C_sendID (char* cardID);

void run_NFC ()
{
  int res = 0x00;

  InitEnv();

  res = InitMode(0x01, 0x01, 0x00);

  if (0x00 == res)
  {
    LogEvent(identity, NFC_STACK_INIT_OK, NULL, logFileDesc);
    WaitDeviceArrival(0x01, NULL, 0x00, C_sendID);
  }
  DeinitPollMode();
}

class NFCNode : public rclcpp::Node
{
public:
  NFCNode()
  : Node("nfc_node")
  {
    publisher_ = this->create_publisher<interfaces::msg::NfcData>("nfc_data", 10);
  }

  void sendID(char* cardID)
  {
    nfc_data.nfc_id = cardID;
    RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", nfc_data.nfc_id.c_str());
    publisher_->publish(nfc_data);
  }

  void init_nfc_data()
  {
    nfc_data.nfc_id = "N/A";
  }

private:
  interfaces::msg::NfcData nfc_data;
  rclcpp::Publisher<interfaces::msg::NfcData>::SharedPtr publisher_;
};

std::shared_ptr<NFCNode> node;

extern "C" void C_sendID (char* cardID)
{
  node->sendID(cardID);
}

int main(int argc, char * argv[])
{
  rclcpp::init(argc, argv);

  node = std::make_shared<NFCNode>();

  rclcpp::executors::SingleThreadedExecutor executor;

  PrepareLoggingEnv(identity);

  std::thread NFC_thread = std::thread(run_NFC);

  cout << "Started the NFC thread ..\n" << endl;
  executor.add_node(node);

  while(1)
  {
    // Spin each second
    executor.spin_once(1000000000ns);
  }
  rclcpp::shutdown();

  return 0;

}
