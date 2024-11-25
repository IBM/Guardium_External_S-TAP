#!/bin/sh
# Copyright 2018 IBM
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LB_HOST="localhost"
LB_CONF=
LB_CONTAINER_HASH=
LB_CONTAINER_NAME="external_stap_lb"
LB_PORT=

# Take a state file created by container_mgmt.sh and build up what the
# load balancer configuration should be
# Format of the file is...
#     Comma separated list of info for container 1
#     Comma separated list of info for container 2
#     ...
#     Comma separated list of info for container n
#
# Where each line contains
#     <host on which container is running>,<external port on host for container>,<internal container listen port>,<listen port on DB>,<container name>
#
# Ignore any line that has "STATE=" in it, as those are for internal use only
lb_import_state() {
	_STATE_FILE=$1

	echo "Load balancer integration - import"

	while read LINE; do
		if echo $LINE | grep -qv "STATE="; then
			LB_TARGET=`echo $LINE | cut -d',' -f1`
			TARGET_PORT=`echo $LINE | cut -d',' -f2`
			LB_PORT=`echo $LINE | cut -d',' -f4`

			echo "Add service node at host $LB_TARGET and external port $TARGET_PORT to LB config"
		fi
	done < $_STATE_FILE

        echo "LB should be listening on port $LB_PORT"
}

# Replace the working copy of the LB configuration with one that just sends traffic
# directly on
lb_redirect_around_containers() {
	_HOST=$1
	_PORT=$2

	echo "LB would send traffic directly to $_HOST:$_PORT instead of to service nodes"
}

# Add a service node to the prepared LB config
lb_add_one() {
	_HOST=$1
	_PORT=$2

	echo "Load balancer integration - add host $_HOST and port $_PORT to LB config"
}

# Remove a service node from the prepared LB config
lb_remove_one() {
	_HOST=$1
	_PORT=$2

	echo "Load balancer integration - remove host $_HOST and port $_PORT from LB config"
}

# Apply the prepared configuration to the load balancer
lb_apply_config() {
	echo "Load balancer integration - apply configuration and tell LB process to read new configuration"
}

# Shut the load balancer down completely
lb_teardown_config() {
	echo "Load balancer integration - teardown LB instance"
}

# Clean up any leftovers
lb_cleanup() {
	echo "Load balancer integration - cleanup"
}
