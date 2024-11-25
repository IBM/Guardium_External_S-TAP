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
LB_USER=
LB_CONF=
LB_CONTAINER_HASH=
LB_CONTAINER_NAME="external_stap_lb"
# Define this to override the LB port.  Useful when deploying services, LB, and
# DB service on the same host since by default the LB uses the DB service port
# and the same port cannot be opened twice
LB_PORT=
# Define this to override the listen IP.  Useful when deploying multiple LB
# services on the same physical host when multiple network interfaces are
# available.
LB_BIND_IP="0.0.0.0"
# Define these to automatically bypass External S-TAP and route directly to
# the DB service in the event that no External S-TAPs are able to accept
# connections
REAL_DB_SERVICE_HOST=
REAL_DB_SERVICE_PORT=

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

	LB_CONF=`mktemp`
	cat > $LB_CONF << EOF
worker_processes  auto;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


stream {
    upstream db_handler {
EOF

	while read LINE; do
		if echo $LINE | grep -qv "STATE="; then
			LB_TARGET=`echo $LINE | cut -d',' -f1`
			TARGET_PORT=`echo $LINE | cut -d',' -f2`
			if [ "$LB_PORT" = "" ]; then
				LB_PORT=`echo $LINE | cut -d',' -f4`
			fi
			cat >> $LB_CONF << EOF
        server $LB_TARGET:$TARGET_PORT;
EOF
		fi
	done < $_STATE_FILE

	if [ "${REAL_DB_SERVICE_HOST}" != "" ] && [ "${REAL_DB_SERVICE_PORT}" != "" ]; then
		cat >> $LB_CONF << EOF
	server ${REAL_DB_SERVICE_HOST}:${REAL_DB_SERVICE_PORT} backup;
EOF
	fi
	cat >> $LB_CONF << EOF
    }

    server {
        listen $LB_PORT;
        proxy_pass db_handler;
    }
}
EOF
}

# Replace the working copy of the LB configuration with one that just sends traffic
# directly on
lb_redirect_around_containers() {
	_HOST=$1
	_PORT=$2

	if [ "$LB_CONF" = "" ] || [ ! -f "$LB_CONF" ]; then
		echo "Fatal error attempting to redirect traffic around the containers with no preliminary LB config file"
		return
	fi

	cat > $LB_CONF << EOF
worker_processes  auto;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


stream {
    upstream db_handler {
	server $_HOST:$_PORT;
    }

    server {
        listen $LB_PORT;
        proxy_pass db_handler;
    }
}
EOF
}

# Add a service node to the prepared LB config
lb_add_one() {
	_HOST=$1
	_PORT=$2

	NEW_LB_CONF=`mktemp`
	:> $NEW_LB_CONF
	while read LINE; do
		if echo $LINE | grep -q "upstream db_handler {"; then
			echo "$LINE" >> $NEW_LB_CONF
			echo "        server $_HOST:$_PORT;" >> $NEW_LB_CONF
		else
			echo "$LINE" >> $NEW_LB_CONF
		fi
	done < $LB_CONF
	cat $NEW_LB_CONF > $LB_CONF
	rm -f $NEW_LB_CONF
}

# Remove a service node from the prepared LB config
lb_remove_one() {
	_HOST=$1
	_PORT=$2

	NEW_LB_CONF=`mktemp`
	:> $NEW_LB_CONF
	while read LINE; do
		if echo $LINE | grep -q "server $_HOST:$_PORT;"; then
			:
		else
			echo "$LINE" >> $NEW_LB_CONF
		fi
	done < $LB_CONF
	cat $NEW_LB_CONF > $LB_CONF
	rm -f $NEW_LB_CONF
}

# Apply the prepared configuration to the load balancer
lb_apply_config() {
	if [ "${LB_USER}" = "" ]; then
		LB_USER=$SVC_HOST_USER
	fi
	if [ "$LB_CONTAINER_HASH" = "" ]; then
		LB_CONTAINER_HASH=`ssh ${LB_USER}@${LB_HOST} docker ps -qf name=$LB_CONTAINER_NAME`
		if [ "$LB_CONTAINER_HASH" = "" ]; then
			if [ "$LB_PORT" != "" ]; then
				ssh ${LB_USER}@${LB_HOST} docker pull nginx:latest
				LB_CONTAINER_HASH=`ssh ${LB_USER}@${LB_HOST} docker run --name $LB_CONTAINER_NAME -p $LB_BIND_IP:$LB_PORT:$LB_PORT -d nginx`
				ssh ${LB_USER}@${LB_HOST} docker exec $LB_CONTAINER_HASH apt-get update
				ssh ${LB_USER}@${LB_HOST} docker exec $LB_CONTAINER_HASH apt-get install -y net-tools
			else
				echo "Error, can't load balance without a port.  Load Balancer port is set to DB server port."
			fi
		fi
	fi

	if [ "$LB_CONTAINER_HASH" = "" ]; then
		echo "Fatal error attempting to start NGINX LB container on host $LB_HOST as user $LB_USER"
	else
		ssh ${LB_USER}@${LB_HOST} rm -rf /tmp/lb_integration
		ssh ${LB_USER}@${LB_HOST} mkdir /tmp/lb_integration
		scp $LB_CONF ${LB_USER}@${LB_HOST}:/tmp/lb_integration/`basename $LB_CONF`
		ssh ${LB_USER}@${LB_HOST} docker cp /tmp/lb_integration/`basename $LB_CONF` ${LB_CONTAINER_HASH}:/etc/nginx/nginx.conf
		ssh ${LB_USER}@${LB_HOST} docker exec $LB_CONTAINER_HASH nginx -s reload
	fi
}

# Shut the load balancer down completely
lb_teardown_config() {
	if [ "${LB_USER}" = "" ]; then
		LB_USER=$SVC_HOST_USER
	fi
	if [ "$LB_CONTAINER_HASH" = "" ]; then
		LB_CONTAINER_HASH=`ssh ${LB_USER}@${LB_HOST} docker ps -qf name=$LB_CONTAINER_NAME`
	fi

	if [ "$LB_CONTAINER_HASH" = "" ]; then
		echo "Load balancer not running"
	else
		# Empty config
		NEW_LB_CONF=`mktemp`
		:> $NEW_LB_CONF
		while read LINE; do
			if echo $LINE | grep -q "server .*:.*;"; then
				:
			else
				echo "$LINE" >> $NEW_LB_CONF
			fi
		done < $LB_CONF
		cat $NEW_LB_CONF > $LB_CONF
		rm -f $NEW_LB_CONF

		ssh ${LB_USER}@${LB_HOST} rm -rf /tmp/lb_integration
		ssh ${LB_USER}@${LB_HOST} mkdir /tmp/lb_integration
		scp $LB_CONF ${LB_USER}@${LB_HOST}:/tmp/lb_integration/`basename $LB_CONF`
		ssh ${LB_USER}@${LB_HOST} docker cp /tmp/lb_integration/`basename $LB_CONF` ${LB_CONTAINER_HASH}:/etc/nginx/nginx.conf
		ssh ${LB_USER}@${LB_HOST} docker exec $LB_CONTAINER_HASH nginx -s reload

		ACTIVE_CONNECTIONS=`ssh ${LB_USER}@${LB_HOST} docker exec $LB_CONTAINER_HASH netstat -an | grep ESTABLISHED`

		if [ "$ACTIVE_CONNECTIONS" = "" ]; then
			# Stop the container
			echo ssh ${LB_USER}@${LB_HOST} docker rm -f $LB_CONTAINER_HASH
			ssh ${LB_USER}@${LB_HOST} docker rm -f $LB_CONTAINER_HASH
		else
			ssh ${LB_USER}@${LB_HOST} docker rename $LB_CONTAINER_NAME ${LB_CONTAINER_NAME}-zombie-$$
			WARNINGS="$WARNINGS\n\
Active connections exist on $LB_HOST $LB_CONTAINER_NAME ($LB_CONTAINER_HASH)\n\
Remove container ${LB_CONTAINER_NAME}-zombie-$$ when safe to do so\n\
\n"
		fi
	fi
}

lb_cleanup() {
	rm -f $LB_CONF
}
