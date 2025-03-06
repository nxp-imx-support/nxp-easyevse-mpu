#!/bin/bash

# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: Apache-2.0

# Environment setup
export OPENSSL_CONF="${OPENSSL_CONF:-/etc/ssl/openssl11_sss_se050.cnf}"
. /etc/profile.d/ros/setup.sh

# This is the order the clients should start. Do not modify it.
clients=("BUSINESS_LOGIC" "GUI" "NFC" "CLOUD" "SEVENSTAX")

function handle_ctrlc()
{
	echo
	echo "Killing all processes..."
	echo
	if [ "$ident" == "EVSE" ]; then
		killall -15 ros2 2> /dev/null
		for client in "${clients[@]}"; do
			if [ "$client" == "SEVENSTAX" ]; then
				killall -15 EVSE_CONTROL 2> /dev/null
			else
				killall -15 $client 2> /dev/null
			fi
		done
	elif [ "$ident" == "PEV" ]; then
		killall -15 PEV_CONTROL 2> /dev/null
	fi
	exit
}

# trapping the SIGINT signal
trap handle_ctrlc SIGINT

declare -i auth_mode
# wakeup SIGBRD
/usr/lib/easyevse/SIGBRD_SYNC IDENT 1> /dev/null
# identify EVSE or PEV
/usr/lib/easyevse/SIGBRD_SYNC IDENT
ret=$?

if [ $ret -eq 2 ]; then
	echo "NO EVSE and PEV be identified"
	exit 1
elif [ $ret -eq 1 ]; then
	ident="PEV"
	eim=0
	pnc=0
	charging=0
	discharging=0
	for arg in "$@"; do
		case $arg in
			EIM)
			let eim++
			;;
			PNC)
			let pnc++
			;;
			C)
			let charging++
			;;
			D)
			let discharging++
			;;
			*)
			;;
		esac
	done

	if [ "$eim" -eq 0 -a "$pnc" -eq 0 ]; then
		echo "No Authorization argument"
		echo "Valid Authorization argument: EIM or PNC"
		exit
	fi

	if [ "$charging" -eq 0 -a "$discharging" -eq 0 ]; then
		echo "No Tranfer mode argument"
		echo "Valid Tranfer Mode argument: C or D"
		exit
	fi

	if [ "$eim" -gt 0 ]; then
		if [ "$charging" -gt 0 ]; then
		/usr/lib/easyevse/PEV_CONTROL EIM C
		elif [ "$discharging" -gt 0 ]; then
		/usr/lib/easyevse/PEV_CONTROL EIM D
		fi
	elif [ "$pnc" -gt 0 ]; then
		if [ "$charging" -gt 0 ]; then
		/usr/lib/easyevse/PEV_CONTROL PNC C
		elif [ "$discharging" -gt 0 ]; then
		/usr/lib/easyevse/PEV_CONTROL PNC D
		fi
	fi

	exit 0
elif [ $ret -eq 0 ]; then
	ident="EVSE"
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
