#!/bin/bash

# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: Apache-2.0

# Environment setup
export OPENSSL_CONF="${OPENSSL_CONF:-/etc/ssl/openssl11_sss_se050.cnf}"
. /etc/profile.d/ros/setup.sh

# This is the order the clients should start. Do not modify it.
clients=("BUSINESS_LOGIC" "GUI" "CLOUD" "NFC" "SEVENSTAX")

function handle_ctrlc()
{
	echo
	echo "Killing all processes..."
	echo
	killall -9 ros2 2> /dev/null
	for client in "${clients[@]}"; do
		killall -9 $client 2> /dev/null
	done
	exit
}

# trapping the SIGINT signal
trap handle_ctrlc SIGINT

if [ $# -eq 0 ]; then
	echo
	echo "ERROR: No argument provided"
	echo "Valid arguments are: NFC, GUI, CLOUD, BUSINESS_LOGIC, SEVENSTAX, all"
	echo
	echo "To start all clients:"
    echo "./easyevse-startup.sh all"
	echo
	echo "To start only the NFC and the GUI clients:"
	echo "./easyevse-startup.sh NFC GUI"
	echo
	exit
fi

if [ $# -eq 1 ] && [ $1 == "all" ]; then
	# Start all clients
	for client in "${clients[@]}"; do
		echo "Starting $client..."
		ros2 run easyevse $client &
		sleep 1
	done
else
	# Start only the specified clients
	# Check if there is any invalid argument
	for arg in $*; do
		if [[ ! " ${clients[@]} " =~ " $arg " ]]; then
			echo
			echo "ERROR: Invalid argument $arg"
			echo "Valid arguments are: NFC, METER, GUI, CLOUD, BUSINESS_LOGIC"
			echo
			exit
		fi
	done

	args=("$@")
	ordered_args=()
	# Order the received arguments in the order in which the clients should start 
	for elem in "${clients[@]}"; do
		if [[ " ${args[@]} " =~ " $elem " ]]; then
			ordered_args+=("$elem")
		fi
	done

	# Start the specified clients
	for arg in ${ordered_args[@]}; do
		echo "Starting $arg..."
		ros2 run easyevse $arg &
		sleep 1
	done
fi

while true; do
	sleep 1
done
