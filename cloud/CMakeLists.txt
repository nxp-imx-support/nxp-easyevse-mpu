cmake_minimum_required (VERSION 3.7)
PROJECT(cloud_app_project C)

# Set Azure IoT SDK C settings
set(use_mqtt ON CACHE  BOOL "Set mqtt on" FORCE )
set(skip_samples ON CACHE  BOOL "Set slip_samples on" FORCE )
set(BUILD_TESTING OFF CACHE  BOOL "Set BUILD_TESTING off" FORCE )

# Add Azure IoT SDK C
add_subdirectory(../azure-iot-sdk-c out)

compileAsC99()

set(iothub_project_files
    ../common/utils.c
    ../common/comms.c
    ../common/logger.c
    cloud_app.c
)

set(AZURE_PROJECT_SOURCE_DIR "../azure-iot-sdk-c")
set(use_sample_trusted_cert ON)
message("AZURE_PROJECT_SOURCE_DIR -->" ${AZURE_PROJECT_SOURCE_DIR})

#Conditionally use the SDK trusted certs in the samples
if(${use_sample_trusted_cert})
    add_definitions(-DSET_TRUSTED_CERT_IN_SAMPLES)
    include_directories(${AZURE_PROJECT_SOURCE_DIR}/certs)
    set(iothub_project_files ${iothub_project_files} ${AZURE_PROJECT_SOURCE_DIR}/certs/certs.c)
endif()

include_directories(${AZURE_PROJECT_SOURCE_DIR}/provisioning_client/inc)
include_directories(.)

add_executable(CLOUD ${iothub_project_files})

target_link_libraries(CLOUD iothub_client
    prov_device_client
    prov_mqtt_transport
    cjson
)

set_target_properties(CLOUD PROPERTIES RUNTIME_OUTPUT_DIRECTORY ../../debug)
