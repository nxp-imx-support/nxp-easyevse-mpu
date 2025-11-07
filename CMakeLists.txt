# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20.0)

project(gui_guider)

FILE(GLOB_RECURSE SOURCES ./custom/*.c ./generated/*.c ports/linux/main.c)

find_package(PkgConfig)
pkg_check_modules(PKG_WAYLAND wayland-client wayland-cursor wayland-protocols xkbcommon)

# include_directories(/usr/local/include)
include_directories(${PROJECT_SOURCE_DIR}/../paho.mqtt.c/src)

# Link against static library instead of dynamic
set(PAHO_MQTT_STATIC_LIB ${PROJECT_SOURCE_DIR}/../paho.mqtt.c/build-aarch64/src/libpaho-mqtt3c.a)

add_executable (gui_guider ${SOURCES})
target_link_libraries (gui_guider PUBLIC lvgl lv_drivers ${PAHO_MQTT_STATIC_LIB} ${PKG_WAYLAND_LIBRARIES})
target_include_directories(gui_guider PRIVATE generated custom generated/guider_customer_fonts generated/guider_fonts generated/images)

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/gui_guider DESTINATION bin)

if(EXISTS ${CMAKE_SOURCE_DIR}/lvgl AND EXISTS ${CMAKE_SOURCE_DIR}/ports/linux/lv_drivers)
add_subdirectory(lvgl)
add_subdirectory(ports/linux/lv_drivers ${CMAKE_CURRENT_BINARY_DIR}/lv_drivers)
target_include_directories(gui_guider PRIVATE lvgl/src lvgl/src/font ports/linux/lv_drivers)
endif()
