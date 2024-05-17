cmake_minimum_required(VERSION 3.5)
project(easyevse)

# Default to C99
if(NOT CMAKE_C_STANDARD)
  set(CMAKE_C_STANDARD 99)
endif()

# Default to C++14
if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 14)
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-w -fpermissive)
endif()

# Set Azure IoT SDK C settings
set(use_mqtt ON CACHE  BOOL "Set mqtt on" FORCE )
set(skip_samples ON CACHE  BOOL "Set slip_samples on" FORCE )
set(BUILD_TESTING OFF CACHE  BOOL "Set BUILD_TESTING off" FORCE )

add_subdirectory(../../azure-iot-sdk-c out)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

include(src/sevenstax/feat_options.cmake)

include_directories(include)
include_directories(.)
include_directories(../../azure-iot-sdk-c/provisioning_client/inc)
include_directories(../../azure-iot-sdk-c/certs)
include_directories(../../azure-iot-sdk-c/iothub_client/inc)
include_directories(../../../recipe-sysroot/usr/include/se05x)

find_package(ament_cmake REQUIRED)
find_package(rclcpp REQUIRED)
find_package(std_msgs REQUIRED)
find_package(Qt6 REQUIRED Widgets Core Quick)
find_package(interfaces REQUIRED)

add_executable(NFC src/nfc/nfcNode.cpp src/nfc/nfc_api.c src/nfc/tools.c src/common/logger.c src/common/utils.c)
add_executable(GUI src/gui/guiNode.cpp src/gui/mainwindow.cpp src/gui/mainwindow.ui src/gui/resources.qrc src/gui/mainwindow.h)
add_executable(CLOUD src/cloud/cloudNode.cpp src/cloud/cloud_api.c src/common/utils.c ../../azure-iot-sdk-c/certs/certs.c src/common/logger.c src/cloud/snw_sss.cpp)
add_executable(BUSINESS_LOGIC src/business_logic/businessLogicNode.cpp)
add_executable(SEVENSTAX src/sevenstax/sevenstaxNode.cpp)

target_compile_definitions(CLOUD PRIVATE 
  -DSET_TRUSTED_CERT_IN_SAMPLES
)

target_compile_definitions(SEVENSTAX PRIVATE
  -DBSDSOCKETRAW_SUPPORTED=$<BOOL:${FEATPROD_BSDSOCKETRAW_SUPPORTED}>
  -DTRGTHW_SUPPORTED=$<BOOL:${FEATPROD_TRGTHW_SUPPORTED}>
  -DIPV6_SUPPORTED=$<BOOL:${FEATPROD_IPV6_SUPPORTED}>
)

target_link_directories(CLOUD PUBLIC "../../../recipe-sysroot/usr/lib")

target_link_libraries(NFC libnfc_nci_linux.so)
target_link_libraries(GUI Qt6Widgets)
target_link_libraries(CLOUD
  iothub_client
  prov_device_client
  prov_mqtt_transport
  cjson
  SSS_APIs
  ex_common
  se05x
  a7x_utils
  smCom
  mwlog
)
target_link_libraries(SEVENSTAX 
  stx_v2g_evse_pnc_cg5317_eth
  gpiod
)

ament_target_dependencies(NFC rclcpp std_msgs interfaces)
ament_target_dependencies(GUI rclcpp std_msgs Qt6Widgets interfaces)
ament_target_dependencies(CLOUD rclcpp std_msgs interfaces)
ament_target_dependencies(BUSINESS_LOGIC rclcpp std_msgs interfaces)
ament_target_dependencies(SEVENSTAX rclcpp std_msgs interfaces)

install(TARGETS
  NFC
  GUI
  CLOUD
  BUSINESS_LOGIC
  SEVENSTAX
  DESTINATION lib/${PROJECT_NAME})

ament_package()
