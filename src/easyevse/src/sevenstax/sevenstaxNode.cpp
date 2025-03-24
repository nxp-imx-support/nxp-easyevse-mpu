/*
 * Copyright 2016 Open Source Robotics Foundation, Inc.
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Informed by the ROS publisher/subscriber tutorials at
 * https://docs.ros.org/en/humble/Tutorials/Beginner-Client-Libraries/Writing-A-Simple-Cpp-Publisher-And-Subscriber.html
 */

#include <chrono>
#include <memory>
#include <unistd.h>

#include "rclcpp/rclcpp.hpp"

#include "interfaces/msg/cloud_data.hpp"
#include "interfaces/msg/general_data.hpp"
#include "interfaces/msg/stack_data.hpp"
#include "interfaces/msg/meter_data.hpp"
#include "interfaces/msg/nfc_data.hpp"
#include "interfaces/msg/gui_data.hpp"
extern "C" {
  #include <stdio.h>
  #include <stdbool.h>
  #include <stdlib.h>
  #include <string.h>
  #include <sys/types.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <time.h>
  #include <pthread.h>
  #include <signal.h>
  #include <mqueue.h>
  #include "easyevse/stx_startup.h"
}

using namespace std::chrono_literals;
using namespace std;

using std::placeholders::_1;

typedef enum TAG_V2G_STATE
{
  PAUSE,
  STOP
} V2G_STATE;

/** \brief Service protocol types */
typedef enum TAG_V2GLIB_PROT
{
    V2GLIB_PROT_UNDEFINED,          /**< Undefined protocol */
    V2GLIB_PROT_DIN12,              /**< DIN70121:2012 protocol schema */
    V2GLIB_PROT_ISO10,              /**< ISO15118:2010 protocol schema */
    V2GLIB_PROT_ISO13,              /**< ISO15118:2013 protocol schema */
    V2GLIB_PROT_ISO20,              /**< ISO15118:2020 protocol schema */
    V2GLIB_PROT_SAE22,              /**< SAE J3105B:2022 protocol schema */
    V2GLIB_PROT_ERROR_DIN12_TLS,    /**< Error during protocol selection, DIN70121-2 in TLS connection */
    V2GLIB_PROT_ERROR_ISO20_TCP,    /**< Error during protocol selection, ISO15118-20 in unsecure TCP connection */
    V2GLIB_PROT_ERROR_ISO20_TLS12   /**< Error during protocol selection, ISO15118-20 in TLS 1.2 connection */
} V2GLIB_PROT;

const char* const states[] = {"PAUSE", "STOP"};
const char name[] = "/stx_mqd";
static void msg_notify_setup(mqd_t *mqdp);
mqd_t mqd = -1;

void sig_handler(int sig)
{
    mq_close(mqd);
    rclcpp::shutdown();
    exit(1);
}
static void notify_thread_func(union sigval sv)
{
    ssize_t num;
    mqd_t *mqdp;
    void *rev_buf;
    struct mq_attr attr;
    mqdp = sv.sival_ptr;
    bool result = true;

    if (mq_getattr(*mqdp, &attr) == -1)
    {
        printf("mq_getattr: errno=%d, desc=%s \n", errno, strerror(errno));
    }
    rev_buf = malloc(attr.mq_msgsize);
    if (rev_buf == NULL)
    {
        printf("malloc: errno=%d, desc=%s \n", errno, strerror(errno));
    }

    msg_notify_setup(mqdp);

    while ((num = mq_receive(*mqdp, (char *)rev_buf, attr.mq_msgsize, NULL)) >=0 )
    {
    }

    if (strcmp(rev_buf, states[0]) == 0)
    {
        stxV2GApplExt_EVSESetChargingSessionPause(&result);
        if (!result)
        {
            printf("Pause request is invalid\n");
        }
    }
    else if (strcmp(rev_buf, states[1]) == 0)
    {
        stxV2GApplExt_EVSEStopCharging(&result);
        rclcpp::shutdown();
    }

    free(rev_buf);
    pthread_exit(NULL);
}

static void msg_notify_setup(mqd_t *mqdp)
{
    struct sigevent sig_ev;
    sig_ev.sigev_notify = SIGEV_THREAD;
    sig_ev.sigev_notify_function = notify_thread_func;
    sig_ev.sigev_notify_attributes = NULL;
    sig_ev.sigev_value.sival_ptr = mqdp;

    if (mq_notify(*mqdp, &sig_ev) == -1)
    {
        printf("mq_notify: errno=%d, desc=%s \n", errno, strerror(errno));
    }
}

class SevenstaxNode : public rclcpp::Node
{
public:
  SevenstaxNode()
  : Node("sevenstax_node")
  {
    meter_data_publisher_ = this->create_publisher<interfaces::msg::MeterData>("meter_data", 10);
    mtimer_ = this->create_wall_timer(
      1000ms, std::bind(&SevenstaxNode::mtimer_callback, this));

    stack_data_publisher_ = this->create_publisher<interfaces::msg::StackData>("stack_data", 10);
    timer_ = this->create_wall_timer(
      1000ms, std::bind(&SevenstaxNode::timer_callback, this));

    cloud_data_subscription_ = this->create_subscription<interfaces::msg::CloudData>(
      "cloud_data", 10, std::bind(&SevenstaxNode::cloud_data_callback, this, _1));

    general_data_subscription_ = this->create_subscription<interfaces::msg::GeneralData>(
      "general_data", 10, std::bind(&SevenstaxNode::general_data_callback, this, _1));
      
    nfc_data_subscription_ = this->create_subscription<interfaces::msg::NfcData>(
      "nfc_data", 10, std::bind(&SevenstaxNode::nfc_data_callback, this, _1));
    
    gui_data_subscription_ = this->create_subscription<interfaces::msg::GuiData>(
      "gui_data", 10, std::bind(&SevenstaxNode::gui_data_callback, this, _1));

  }

  void init_stack_data_pre()
  {
    cloud_data.grid_pwr_lim = 32.0;
    cloud_data.tariff_cost = 9.0;
    cloud_data.tariff_rate = 10.0;
    cloud_data.grid_stop_req = false;

    stack_data.energy_transfer_dir = -1;
    
    nfc_data.nfc_id = "NULL";
  }

  void init_stack_data() 
  {
    gui_data.user_stop_req = false;
    gui_data.user_pause_req = false;

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
    general_data.evse_rating = 32;

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

private:

  void setMaxCurrentLimit()
  {
    bool result;

    RCLCPP_INFO(this->get_logger(), "setMaxCurrentLimit: general_data.evse_rating=%d,  cloud_data.grid_pwr_lim=%f", general_data.evse_rating, cloud_data.grid_pwr_lim);
    if(general_data.evse_rating >= cloud_data.grid_pwr_lim)
    {
      stxV2GApplExt_EVSESetMaxACCurrentLimit(cloud_data.grid_pwr_lim, &result);
    }
    else
    {
      stxV2GApplExt_EVSESetMaxACCurrentLimit(general_data.evse_rating, &result);
    } 
  }
  
  void gui_data_callback(const interfaces::msg::GuiData::SharedPtr msg)
  {
    bool result;

    if((gui_data.user_pause_req != msg->user_pause_req))
    {
      gui_data.user_pause_req = msg->user_pause_req;
      if(gui_data.user_pause_req)
        stxV2GApplExt_EVSESetChargingSessionPause(&result);
    }
  }

  void cloud_data_callback(const interfaces::msg::CloudData::SharedPtr msg)
  {
    bool result = false, tempb = false;
    
    RCLCPP_INFO(this->get_logger(), "%s: %d", __func__, __LINE__);
    
    if(cloud_data.grid_pwr_lim != msg->grid_pwr_lim)
    {
      cloud_data.grid_pwr_lim = msg->grid_pwr_lim;

      if(stack_data.charging)
      {
        setMaxCurrentLimit();
      }
    }
    cloud_data.tariff_cost = msg->tariff_cost;
    cloud_data.tariff_rate = msg->tariff_rate;
    

    if(cloud_data.grid_stop_req != msg->grid_stop_req && stack_data.charging)
    {
      cloud_data.grid_stop_req = msg->grid_stop_req;
      if(cloud_data.grid_stop_req)
      {
        stxV2GApplExt_EVSEGetCharging(&tempb, &result);
        if(tempb)
        {
          RCLCPP_INFO(this->get_logger(), "Cloud requesting to stop charging");
          stxV2GApplExt_EVSEStopCharging(&result);
        }
      }    
    }
  }

  void general_data_callback(const interfaces::msg::GeneralData::SharedPtr msg)
  {
    bool result = false;
    general_data.fw_vers = msg->fw_vers;
    general_data.lat = msg->lat;
    general_data.lon = msg->lon;
    general_data.alt = msg->alt;
    general_data.temperature = msg->temperature;

    if(general_data.evse_id != msg->evse_id)
    {
      general_data.evse_id = msg->evse_id;
      stxV2GApplExt_EVSESetEVSEID(general_data.evse_id.c_str(), &result);
    }
    //RCLCPP_INFO(this->get_logger(), "Publishing EVSE_ID: '%s'", general_data.evse_id.c_str());
    if(general_data.evse_rating != msg->evse_rating && stack_data.charging)
    {
      general_data.evse_rating = msg->evse_rating;
      setMaxCurrentLimit();
    }
  }

  void nfc_data_callback(const interfaces::msg::NfcData::SharedPtr msg)
  {
    bool result = false;
    bool CardScanned = false;
    nfc_data.nfc_id = msg->nfc_id;
    RCLCPP_INFO(this->get_logger(), "Card was scanned");    
    if (strlen(nfc_data.nfc_id.c_str())>2)
    {
      CardScanned = true;
      stxV2GApplExt_EVSESetCardScanned(&CardScanned, &result);
    }
  }

  void timer_callback()
  {
    bool result = false, tempb = false;
    uint32_t templ = 0;
    uint64_t templl = 0;
    double tempd = 0.0;

    stxV2GApplExt_EVSEGetApplV2GStarted(&tempb, &result);
    if(result)
    {
      stxV2GApplExt_EVSEGetChargingState(&templ, &result);
      stack_data.chg_state = (char) (templ + 'A'); 
      //RCLCPP_INFO(this->get_logger(), "Publishing Chgstate: '%s'", stack_data.chg_state.c_str());
      stxV2GApplExt_EVSEGetCommunicationLevel(&tempb, &result);
      if(tempb)
      {
        stack_data.protocol = "BASIC";
      }
      else
      {
        uint8_t ucSchemaIdSelected = 0;
        uint32_t ulProtSelected = 0;
        bool bMinorDeviation;

        stxV2GApplExt_EVSECheckSupportedAppProtocol(&ulProtSelected, &bMinorDeviation, &result);
        if(ulProtSelected == V2GLIB_PROT_ISO20)
            stack_data.protocol = "ISO15118-20";
        else if(ulProtSelected == V2GLIB_PROT_ISO13)
            stack_data.protocol = "ISO15118-2";
        else
            stack_data.protocol = "ISO15118";
      }
      //RCLCPP_INFO(this->get_logger(), "Publishing CommunicationLevel: '%s'", stack_data.protocol.c_str());
      stxV2GApplExt_EVSEGetCharging(&stack_data.charging, &result);
      //RCLCPP_INFO(this->get_logger(), "Publishing Charging: '%d'", stack_data.charging); 
      if(stack_data.charging)
      {
        stxV2GApplExt_EVSEGetEamount(&stack_data.energy_requested, &result);
        //RCLCPP_INFO(this->get_logger(), "Publishing RequestedEnergy: '%.2f'", stack_data.energy_requested);
        stxV2GApplExt_EVSEGetDeliveredEnergy(&stack_data.energy_delivered, &result);
        //RCLCPP_INFO(this->get_logger(), "Publishing DeliveredEnergy: '%.2f'", stack_data.energy_delivered);    
        stxV2GApplExt_EVSEGetAuthenticationStatus(&tempb, &result);
        if(tempb)
        {
          stack_data.vehicle_auth = "PASS";
        }
        else
        {
          stack_data.vehicle_auth = "FAIL";
        }
        //RCLCPP_INFO(this->get_logger(), "Publishing AuthStatus: '%s'", stack_data.vehicle_auth.c_str());
        stxV2GApplExt_EVSEGetDeliveredCurrent(&tempd, &result);
        stack_data.chg_rate = tempd;
        //RCLCPP_INFO(this->get_logger(), "Publishing ChgRate: '%d'", stack_data.chg_rate);
#define EVCCID_BUF_SZ (256)
        char evccid_buf[EVCCID_BUF_SZ];
        strncpy(evccid_buf, stack_data.evcc_id.c_str(), EVCCID_BUF_SZ);
        stxV2GApplExt_EVSEGetEVCCID(evccid_buf, &result);
        stack_data.evcc_id = string(evccid_buf);
        //RCLCPP_INFO(this->get_logger(), "Publishing EVCCID: '%s'", stack_data.evcc_id);
        stxV2GApplExt_EVSEGetElapsedTime(&templl, &result);
        getTime(templl, &stack_data.chg_elapsed_time);
        //RCLCPP_INFO(this->get_logger(), "Publishing Elapsed Time: '%s'", stack_data.chg_elapsed_time.c_str());
        stxV2GApplExt_EVSEGetRemainingTime(&templl, &result);
        getTime(templl, &stack_data.chg_remaining_time);
        //RCLCPP_INFO(this->get_logger(), "Publishing Remaining Time: '%s'", stack_data.chg_remaining_time.c_str());
      }

      stack_data.chg_cost = stack_data.energy_delivered * cloud_data.tariff_cost;
      //RCLCPP_INFO(this->get_logger(), "Publishing ChargeCost: '%.2f'", stack_data.chg_cost);
      
      stxV2GApplExt_EVSEGetEnergyTransferDir(&stack_data.energy_transfer_dir, &result);
      stxV2GApplExt_EVSEGetPresentSOC(&stack_data.present_soc, &result);
      stxV2GApplExt_EVSEGetEvPresentVoltageDis(&stack_data.ev_present_voltage_dis, &result);
      stxV2GApplExt_EVSEGetEvPresentCurrentDis(&stack_data.ev_present_current_dis, &result);
      stxV2GApplExt_EVSEGetChargingSessionPause(&stack_data.is_pausing, &result);

      stack_data_publisher_->publish(stack_data);
    }
  }

  void getTime(uint64_t timediff, string * time)
  {
    uint64_t proc_time = timediff/1000;
    uint16_t hours = 0, minutes = 0, seconds = 0;

    seconds = proc_time % 60;
    proc_time /= 60;

    minutes = proc_time % 60;
    proc_time /= 60;

    hours = proc_time;

    //RCLCPP_INFO(this->get_logger(), "Publishing Time: '%d' '%d' '%d'", hours, minutes, seconds);

    *time = to_string(hours%100) + "H:" + to_string(minutes) + "M:" + to_string(seconds) + "S";

    //RCLCPP_INFO(this->get_logger(), "Publishing Time: '%s'", time->c_str());
  }

  void mtimer_callback()
  {
    bool result = false;

    if(stack_data.charging)
    {
      stxV2GApplExt_EVSEGetDeliveredCurrent(&meter_data.current, &result);
      stxV2GApplExt_EVSEGetDeliveredVoltage(&meter_data.voltage, &result);
      stxV2GApplExt_EVSEGetDeliveredPower(&meter_data.power, &result);
      //RCLCPP_INFO(this->get_logger(), "Publishing Current: '%.2f'", meter_data.current);
      //RCLCPP_INFO(this->get_logger(), "Publishing Voltage: '%.2f'", meter_data.voltage);
      //RCLCPP_INFO(this->get_logger(), "Publishing Power: '%.2f'", meter_data.power);
      meter_data_publisher_->publish(meter_data);
    }
  }

  interfaces::msg::CloudData cloud_data;
  interfaces::msg::GeneralData general_data;
  interfaces::msg::MeterData meter_data;
  interfaces::msg::NfcData nfc_data;
  interfaces::msg::StackData stack_data;
  interfaces::msg::GuiData gui_data;

  rclcpp::TimerBase::SharedPtr mtimer_, timer_ ;

  rclcpp::Publisher<interfaces::msg::MeterData>::SharedPtr meter_data_publisher_;
  rclcpp::Publisher<interfaces::msg::StackData>::SharedPtr stack_data_publisher_;
  rclcpp::Subscription<interfaces::msg::CloudData>::SharedPtr cloud_data_subscription_;
  rclcpp::Subscription<interfaces::msg::GeneralData>::SharedPtr general_data_subscription_;
  rclcpp::Subscription<interfaces::msg::MeterData>::SharedPtr meter_data_subscription_;
  rclcpp::Subscription<interfaces::msg::NfcData>::SharedPtr nfc_data_subscription_;
  rclcpp::Subscription<interfaces::msg::GuiData>::SharedPtr gui_data_subscription_;
};

std::shared_ptr<SevenstaxNode> node;

int main(int argc, char * argv[])
{
  mqd = mq_open(name, O_RDONLY | O_NONBLOCK);
  if (mqd == (mqd_t)-1)
  {
    printf("mq_open: errno=%d, desc=%s \n", errno, strerror(errno));
  }
  msg_notify_setup(&mqd);

  signal(SIGTERM, sig_handler);

  rclcpp::init(argc, argv);

  node = std::make_shared<SevenstaxNode>();

  node->init_stack_data_pre();

  rclcpp::executors::SingleThreadedExecutor executor;

  std::thread sevenstax_thread = std::thread(stx_startup,argc,argv);

  cout << "Started the stx thread ..\n" << endl;
  executor.add_node(node);
  while(1)
  {
    // Refresh every 500ms
    executor.spin_once(5 * 100000000ns);
  }
  rclcpp::shutdown(); 
  return 0;
}
