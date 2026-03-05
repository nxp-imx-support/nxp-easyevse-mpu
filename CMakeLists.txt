# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20.0)

project(gui_guider)

FILE(GLOB_RECURSE SOURCES ./custom/*.c ./generated/*.c ports/linux/main.c)

find_package(PkgConfig)
pkg_check_modules(
    PKG_WAYLAND REQUIRED
        wayland-client
        wayland-cursor
        wayland-protocols
        xkbcommon
)

find_path(PAHO_INCLUDE_DIR
    NAMES MQTTClient.h
    PATH_SUFFIXES paho-mqtt
)

find_library(PAHO_MQTT_LIB
    NAMES paho-mqtt3c
)

if(NOT PAHO_INCLUDE_DIR OR NOT PAHO_MQTT_LIB)
    message(FATAL_ERROR
        "Paho MQTT C not found:\n"
        "  PAHO_INCLUDE_DIR='${PAHO_INCLUDE_DIR}'\n"
        "  PAHO_MQTT_LIB='${PAHO_MQTT_LIB}"
    )
endif()

add_executable (gui_guider ${SOURCES})

target_include_directories(gui_guider
    PRIVATE
        ${PAHO_INCLUDE_DIR}
        generated
        custom
        generated/guider_customer_fonts
        generated/guider_fonts
        generated/images
)

target_link_libraries(gui_guider
    PUBLIC
        lvgl
        lv_drivers
        ${PAHO_MQTT_LIB}
        ${PKG_WAYLAND_LIBRARIES}
)

if(EXISTS ${CMAKE_SOURCE_DIR}/lvgl AND EXISTS ${CMAKE_SOURCE_DIR}/ports/linux/lv_drivers)
add_subdirectory(lvgl)
add_subdirectory(ports/linux/lv_drivers ${CMAKE_CURRENT_BINARY_DIR}/lv_drivers)
target_include_directories(gui_guider PRIVATE lvgl/src lvgl/src/font ports/linux/lv_drivers)
endif()

install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/gui_guider DESTINATION bin)
