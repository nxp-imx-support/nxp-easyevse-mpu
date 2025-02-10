#!/bin/bash

# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: Apache-2.0

# Environment setup
export OPENSSL_CONF="${OPENSSL_CONF:-/etc/ssl/openssl11_sss_se050.cnf}"
. /etc/profile.d/ros/setup.sh

# This is the order the clients should start. Do not modify it.
clients=("BUSINESS_LOGIC" "GUI" "NFC" "SEVENSTAX" "CLOUD")

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

declare -i auth_mode
# identify EVSE or PEV
/usr/lib/easyevse/IDENT
if [ $? -eq 2 ]; then
	echo "NO EVSE and PEV be identified"
	exit 1
elif [ $? -eq 1 ]; then
	auth_mode=0
	for arg in "$@"; do
		if [ "$arg" == "EIM" ]; then
			let auth_mode++
		fi
	done

	if [ "$auth_mode" -gt 0 ]; then
		/usr/lib/easyevse/PEV_CONTROL EIM
	else
		/usr/lib/easyevse/PEV_CONTROL
	fi

	exit 0
fi

if [ $# -eq 0 ]; then
	echo
	echo "ERROR: No argument provided"
	echo "Valid arguments are: BUSINESS_LOGIC, GUI, NFC, SEVENSTAX, CLOUD, all"
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
		if [ "$client" == "SEVENSTAX" ]; then
			/usr/lib/easyevse/EVSE_CONTROL
		else
			ros2 run easyevse $client &
		sleep 1
		fi
	done
else
	# Start only the specified clients
	# Check if there is any invalid argument
	for arg in $*; do
		if [[ ! " ${clients[@]} " =~ " $arg " ]]; then
			echo
			echo "ERROR: Invalid argument $arg"
			echo "Valid arguments are: BUSINESS_LOGIC, GUI, NFC, SEVENSTAX, CLOUD"
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
		if [ "$arg" == "SEVENSTAX" ]; then
			/usr/lib/easyevse/EVSE_CONTROL
		else
			ros2 run easyevse $arg &
		sleep 1
		fi
	done
fi

while true; do
	sleep 1
done
