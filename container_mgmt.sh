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

###################################
# Pre-requisite checking for script

TRANSLATE_SPECIAL_CHARS=1
ECHO_DASH_N_WORKS=0
PRINTF_IS_PROVIDED=0

A="1\n2"

if [ `echo "$A" | wc -l | awk '{ gsub(/[ \t\n]+/, "", $0); printf $0; }'` -eq 2 ]; then
	# echo will translate special chars for us so no need to filter through awk
	TRANSLATE_SPECIAL_CHARS=0
fi

A=`echo -n`

if [ "$A" = "" ]; then
	# echo -n is recognized so we can avoid printing newlines like this
	ECHO_DASH_N_WORKS=1
fi

if type printf > /dev/null 2>&1; then
	PRINTF_IS_PROVIDED=1
fi

print() {
	MSG="$1"
	if [ $TRANSLATE_SPECIAL_CHARS -eq 1 ]; then
		echo "$MSG" | awk '{ gsub(/\\t/, "\t", $0); gsub(/\\n/, "\n", $0); printf $0; }'
	else
		if [ $PRINTF_IS_PROVIDED -eq 1 ]; then
			printf "$MSG"
		elif [ $ECHO_DASH_N_WORKS -eq 1 ]; then
			echo -n "$MSG"
		else
			echo "$MSG"
		fi
	fi
}

println() {
	MSG="$1"
	if [ $TRANSLATE_SPECIAL_CHARS -eq 1 ]; then
		echo "$MSG" | awk '{ gsub(/\\t/, "\t", $0); gsub(/\\n/, "\n", $0); print $0; }'
	else
		echo "$MSG"
	fi
}

UTILITY_MISSING=0
check_for_utility() {
	UTILITY=$1
	if ! type $UTILITY > /dev/null 2>&1; then
		echo "Missing required utility for proper script function: $UTILITY"
		UTILITY_MISSING=1
	fi
}

check_for_utility expr

if [ $UTILITY_MISSING -ne 0 ]; then
	exit 1
fi
###################################

if [ "$DEVELOPER" != "" ]; then
	if [ ! -f $DEVELOPER ]; then
		echo "Developer script $DEVELOPER not found!"
		exit 1
	fi
	. $DEVELOPER
	if [ $? -ne 0 ]; then
		echo "Error sourcing developer script $DEVELOPER"
		exit 1
	fi
else
	# Define stubs for the developer operations
	developer_usage()     {
		:
	}
	developer_arg_parse() {
		return 0
	}
	is_developer() {
		return 1
	}
	is_developer_option() {
		return 1
	}
	developer_option_extra_shift() {
		return 1
	}
	developer_param_sanity() {
		:
	}
	is_developer_cluster() {
		return 1
	}
	developer_have_additional_containers() {
		return 1
	}
	developer_additional_containers_param_check() {
		:
	}
	developer_note_additional_containers() {
		:
	}
	developer_cluster_interactive_setup() {
		:
	}
	developer_additional_containers_creation() {
		:
	}
	developer_additional_containers_msgs() {
		:
	}
	developer_cluster_create_config() {
		:
	}
	developer_cluster_set_command() {
		:
	}
	developer_cluster_make_container() {
		:
	}
	is_developer_automated_changes() {
		:
	}
	developer_do_cluster_postconfig() {
		:
	}
	developer_do_automated_postconfig() {
		:
	}
	developer_create_cleanup() {
		:
	}
	is_developer_container() {
		return 1
	}
fi

do_usage() {
	println "usage: `basename $0` [options]"
	println "options"
	developer_usage
	println "\t[--lb-script <file>]                    - script to use to pull in functions for integrating with a load balancer"
	println "\t                                          if not provided, load balancer will need to be configured separately"
	println
	println "\t[--svc-host <host/ip>]                  - host(s) on which to create service container(s) (comma delimited)"
	println "\t                                          optional, default is \"$SVC_HOST\""
	println "\t[--svc-host-user <username>]            - username to use for creating service container(s) on host(s)"
	println "\t                                          optional, default is the current user \"$SVC_HOST_USER\""
	println "\t[--svc-port-range <X-Y>]                - exported port for the service container will be between X and Y (inclusive)"
	println "\t                                          optional, default (\"0\") is to use the values at /proc/sys/net/ipv4/ip_local_port_range"
	println "\t                                          example \"32768-61000\""
	println "\t[--svc-image <image>]                   - hash/name of guardium external s-tap image"
	println "\t                                          required, example \"ibmcorp/guardium_external_s-tap:v10_6_0\""
	println "\t[--repo-user <username>]                - username to log in to the repository from which the service image is pulled"
	println "\t                                          optional, example \"foo\""
	println "\t[--repo-pass <password>]                - password for username when loging in to the repository"
	println "\t                                          optional, example \"bar\""
	println "\t[--svc-container-num <num>]             - number of service containers to create"
	println "\t                                          optional, default is \"1\""
	println
	println "\t[--ni]                                  - run this script non-interactively"
	println "\t[--c]                                   - create a cluster"
	println "\t[--p]                                   - do not create a cluster, just print service container env vars (output saved in state file)"
	println "\t[--r]                                   - remove interception (requires load-balancer integration script)"
	println "\t[--e]                                   - enable interception (requires load-balancer integration script)"
	println "\t[--u]                                   - upgrade an existing cluster"
	println "\t[--d]                                   - delete an existing cluster"
	println "\t[--z]                                   - clean up zombie instances"
	println
	println "\t[--uuid <UUID>]                         - specify <UUID> for the guardium external s-tap cluster"
	println "\t                                          optional, default is a random UUID like \"$RANDOM_UUID\""
	println
	println "\tWhen intercepting TLS traffic, a certificate/key pair is required for External"
	println "\tS-TAP.  This information is retrieved from the collector in one of two ways..."
	println
	println "\t\tUsing a secret token to retrieve a certificate/key from the collector"
	println "\t\t[--proxy-secret <string>]               - use <string> as shared secret to retrieve key from collector, comes from CLI on collector"
	println
	println "\t\tGenerating a CSR in the container to be signed by the collector"
	println "\t\t[--proxy-csr-name         <string>]     - Name field of CSR's CN (required if using this method)"
	println "\t\t[--proxy-csr-country      <string>]     - Country field of CSR's CN (optional)"
	println "\t\t[--proxy-csr-province     <string>]     - Province field of CSR's CN (optional)"
	println "\t\t[--proxy-csr-city         <string>]     - City field of CSR's CN (optional)"
	println "\t\t[--proxy-csr-organization <string>]     - Organization field of CSR's CN (optional)"
	println "\t\t[--proxy-csr-keylength       <num>]     - Private key length, default $DEFAULT_CSR_KEYLENGTH (optional)"
	println "\t\t[--proxy-secret           <string>]     - use <string> as shared secret to authorize signing the CSR"
	println
	println "\t[--sqlguard-ip <host/ip>]               - specify collector list <host/ip> (comma delimited) for guardium external s-tap to relay decrypted traffic (primary is first)"
	println "\t[--tenant-id <tenant ID string>]        - specify tenant ID for this deployment"
	println "\t                                          required, example \"10.0.0.2\""
	println "\t[--participate-in-load-balancing <num>] - STAP load balancing parameter"
	println "\t                                          optional, default is 0 -  0: failover/no lb, 1: split, 2: redundancy, 3: not allowed, 4: threaded"
	println "\t[--sqlguard-cert-cn <cn>]               - CN to match when verifying collector certificates"
	println "\t                                          requires a derived container image with a CA populated at ${GUARDIUM_CA_PATH}"
	println "\t[--db-host <host/ip>]                   - database <host/ip> to which cluster sends traffic"
	println "\t                                          optional, can be set from collector after creation.  example \"10.0.0.3\""
	println "\t[--db-port <port>]                      - database <port> to which cluster sends traffic"
	println "\t                                          optional, can be set from collector after creation.  example \"1526\""
	println "\t[--db-type <string>]                    - specify DB type for traffic that is being proxied"
	println "\t                                          optional, can be set from collector after creation."
	println "\t                                          must be one of \"oracle\", \"mssql\", \"sybase\", \"mongodb\", \"db2\", \"mysql\", \"memsql\", \"mariadb\", \"pgsql\", \"greenplumdb\", \"verticadb\", \"redis\", \"dynamodb\", \"el_search\", \"amazons3\", \"cockroach\", \"netezza\", \"hana\", \"snowflake\", \"trd\", \"couch\" or \"milvus\""
	println "\t[--proxy-num-workers <#>]               - number of worker threads for the guardium external s-tap to use"
	println "\t                                          optional, can be set from collector after creation.  example \"5\""
	println "\t[--proxy-protocol <#>]                  - proxy protocol is enabled for the DB traffic (0: no, 1: protocol version 1, 2: protocol version 2)"
	println "\t                                          optional, can be set from collector after creation.  default is \"0\""
	println "\t[--invalid-cert-disconnect]             - disconnect if DB server certificate cannot be verified"
	println "\t                                          optional, can be set from collector after creation."
	println "\t[--invalid-cert-notify]                 - log a warning if DB server certificate cannot be verified"
	println "\t                                          optional, can be set from collector after creation."
	println "\t[--override-server-ip <ip>              - optional, override server IP with that specified"
	println
	println "\t[--kill-after <#>]                      - when stopping a container, if container cannot shutdown within # seconds, forcefully remove it"
	println "\t                                          optional, example \"30\", when not specified, script will wait 30s but container will not be"
	println "\t                                          forefully removed if graceful termination does not occur."
	println
	println "\t[--state-file <filename>]               - name of the file in which the state is recorded"
	println "\t                                          required, example \"./cluster_state\""
	println "\t[--envvar <env-setting>]                - extra environment variable setting"
#	println "\t[--mount <location>:<mountpoint>]       - mount source:destination"
#	println "\t[--volume <volume:/mountpoint:options>] - Docker volume mount"
	println "\t[--persistent <volume>]                 - persistent storage source"
}

# This script will need to save a config file for future use
# will copy itself and run itself on a target system


# ------------------------------------------------
# Variables

ERROR=0
HASHES=""
ACTION=""

# Defaults
# We used to require NET_ADMIN to set iptables rules, but now we rely on
# the host system not exposing ports to restrict container access since
# most cloud services warn about NET_ADMIN privilege
#REQUIRED_CAPABILITIES="--cap-add=NET_ADMIN"
REQUIRED_CAPABILITIES=""
LISTEN_PORT=8888

RANDOM_UUID=""
if type uuidgen > /dev/null 2>&1; then
	RANDOM_UUID=`uuidgen`
fi

SUGGESTED_CORE_PATTERN="/tmp/core.%t.%e.%p"

# These need to be filled in
STAP_CONFIG_TAP_TAP_IP_FMT="-e STAP_CONFIG_TAP_TAP_IP="
STAP_CONFIG_TAP_PRIVATE_TAP_IP_FMT="-e STAP_CONFIG_TAP_PRIVATE_TAP_IP="
STAP_CONFIG_TAP_FORCE_SERVER_IP_FMT="-e STAP_CONFIG_TAP_FORCE_SERVER_IP="
STAP_CONFIG_TAP_TENANT_ID_FMT="-e STAP_CONFIG_TAP_TENANT_ID="

STAP_CONFIG_PROXY_GROUP_MEMBER_COUNT_FMT="-e STAP_CONFIG_PROXY_GROUP_MEMBER_COUNT="
STAP_CONFIG_PROXY_GROUP_UUID_FMT="-e STAP_CONFIG_PROXY_GROUP_UUID="
STAP_CONFIG_PROXY_DB_HOST_FMT="-e STAP_CONFIG_PROXY_DB_HOST="
STAP_CONFIG_DB_0_REAL_DB_PORT_FMT="-e STAP_CONFIG_DB_0_REAL_DB_PORT="
STAP_CONFIG_PROXY_LISTEN_PORT_FMT="-e STAP_CONFIG_PROXY_LISTEN_PORT="
STAP_CONFIG_PROXY_DEBUG_FMT="-e STAP_CONFIG_PROXY_DEBUG="

STAP_CONFIG_PROXY_SECRET_FMT="-e STAP_CONFIG_PROXY_SECRET="

STAP_CONFIG_PROXY_CSR_NAME_FMT="-e STAP_CONFIG_PROXY_CSR_NAME="
STAP_CONFIG_PROXY_CSR_COUNTRY_FMT="-e STAP_CONFIG_PROXY_CSR_COUNTRY="
STAP_CONFIG_PROXY_CSR_PROVINCE_FMT="-e STAP_CONFIG_PROXY_CSR_PROVINCE="
STAP_CONFIG_PROXY_CSR_CITY_FMT="-e STAP_CONFIG_PROXY_CSR_CITY="
STAP_CONFIG_PROXY_CSR_ORGANIZATION_FMT="-e STAP_CONFIG_PROXY_CSR_ORGANIZATION="
STAP_CONFIG_PROXY_CSR_KEYLENGTH_FMT="-e STAP_CONFIG_PROXY_CSR_KEYLENGTH="

STAP_CONFIG_DB_0_DB_TYPE_FMT="-e STAP_CONFIG_DB_0_DB_TYPE="
STAP_CONFIG_SQLGUARD_FMT="-e STAP_CONFIG_SQLGUARD_"
STAP_CONFIG_SQLGUARD_IP_FMT="_SQLGUARD_IP="
SQLGUARD_PARAMS=
STAP_CONFIG_PARTICIPATE_IN_LOAD_BALANCING_FMT="-e STAP_CONFIG_PARTICIPATE_IN_LOAD_BALANCING="
STAP_CONFIG_GUARDIUM_CA_PATH_FMT="-e STAP_CONFIG_GUARDIUM_CA_PATH="
STAP_CONFIG_SQLGUARD_CERT_CN_FMT="-e STAP_CONFIG_SQLGUARD_CERT_CN="
STAP_CONFIG_PROXY_NUM_WORKERS_FMT="-e STAP_CONFIG_PROXY_NUM_WORKERS="
STAP_CONFIG_PROXY_PROXY_PROTOCOL_FMT="-e STAP_CONFIG_PROXY_PROXY_PROTOCOL="
STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE_FMT="-e STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE="
STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE_FMT="-e STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE="

# These can be filled in by parameters
TAP_IP="NULL"
PRIVATE_TAP_IP="NULL"
FORCE_SERVER_IP=0
NUMBER_OF_CONTAINERS=""
DEBUG=0
CONTAINER_SHMEM_MEMORY_REQ=500
CONTAINER_STAP_MEMORY_REQ=200
CONTAINER_EXTRA_MEMORY_REQ=300
CONTAINER_RECOMMENDED_MEMORY_FREE=`expr ${CONTAINER_SHMEM_MEMORY_REQ} + ${CONTAINER_STAP_MEMORY_REQ} + ${CONTAINER_EXTRA_MEMORY_REQ}`
EXTRA_CAPABILITIES="--shm-size ${CONTAINER_SHMEM_MEMORY_REQ}M"


LB_SCRIPT=""

LOCAL_DOCKER_CMD="docker"
REMOTE_DOCKER_CMD="docker"
type podman > /dev/null 2>&1
if [ $? -eq 0 ]; then
	LOCAL_DOCKER_CMD="podman"
fi

PRIVILEGED=""
SVC_IMAGE=""
SVC_PORT_RANGE="0"
SVC_HOST="localhost"
SVC_HOST_USER=`whoami`
SVC_HOST_EXPORT_ANY_IP=":"
REPO_USER=""
REPO_PASS=""

UUID=""
DB_HOST=""
DB_PORT=""
DB_TYPE=""

TOKEN=""

CSR_NAME=""
CSR_COUNTRY=""
CSR_PROVINCE=""
CSR_CITY=""
CSR_ORGANIZATION=""
DEFAULT_CSR_KEYLENGTH=2048
CSR_KEYLENGTH=$DEFAULT_CSR_KEYLENGTH

COLLECTOR=""
TENANT_ID=""
GUARDIUM_CA_PATH="/etc/guardium/guardium_ca.crt"
PARTICIPATE_IN_LOAD_BALANCING=0
NUM_WORKERS=""
PROXY_PROTOCOL="0"
INVALID_CERT_DISCO="N"
INVALID_CERT_NOTIFY="N"

KILL_AFTER=0

STATE_FILE=

ENVVARS=""
MOUNTS=

NI=0

parse_cmd_line_args()
{
	developer_arg_parse $@
	while [ $# -gt 0 ];
	do
		THIS_PARAM=$1
		if ! is_developer_option $THIS_PARAM; then
			case "$THIS_PARAM" in
				--lb-script)
					LB_SCRIPT=$2
					shift
					;;
				--ni)
					NI=1
					;;
				--c)
					if [ "$ACTION" != "" ]; then
						echo "Only one of --c, --p, --r, --e, --u, --d, or --z may be specified"
						do_usage
						exit 1
					fi
					ACTION="C"
					;;
				--p)
					if [ "$ACTION" != "" ]; then
						echo "Only one of --c, --p, --r, --e, --u, --d, or --z may be specified"
						do_usage
						exit 1
					fi
					ACTION="P"
					;;
				--r)
					if [ "$ACTION" != "" ]; then
						echo "Only one of --c, --p, --r, --e, --u, --d, or --z may be specified"
						do_usage
						exit 1
					fi
					ACTION="R"
					;;
				--e)
					if [ "$ACTION" != "" ]; then
						echo "Only one of --c, --p, --r, --e, --u, --d, or --z may be specified"
						do_usage
						exit 1
					fi
					ACTION="E"
					;;
				--u)
					if [ "$ACTION" != "" ]; then
						echo "Only one of --c, --p, --r, --e, --u, --d, or --z may be specified"
						do_usage
						exit 1
					fi
					ACTION="U"
					;;
				--d)
					if [ "$ACTION" != "" ]; then
						echo "Only one of --c, --p, --r, --e, --u, --d, or --z may be specified"
						do_usage
						exit 1
					fi
					ACTION="D"
					;;
				--z)
					if [ "$ACTION" != "" ]; then
						echo "Only one of --c, --p, --r, --e, --u, --d, or --z may be specified"
						do_usage
						exit 1
					fi
					ACTION="Z"
					;;
				--svc-container-num)
					NUMBER_OF_CONTAINERS=$2
					shift
					;;
				--uuid)
					UUID=$2
					shift
					;;
				--db-host)
					DB_HOST=$2
					shift
					;;
				--db-port)
					DB_PORT=$2
					shift
					;;
				--proxy-secret)
					TOKEN=$2
					shift
					;;
				--proxy-csr-name)
					CSR_NAME=$2
					shift
					;;
				--proxy-csr-country)
					CSR_COUNTRY=$2
					shift
					;;
				--proxy-csr-province)
					CSR_PROVINCE=$2
					shift
					;;
				--proxy-csr-city)
					CSR_CITY=$2
					shift
					;;
				--proxy-csr-organization)
					CSR_ORGANIZATION=$2
					shift
					;;
				--proxy-csr-keylength)
					CSR_KEYLENGTH=$2
					shift
					;;
				--proxy-num-workers)
					NUM_WORKERS=$2
					shift
					;;
				--proxy-protocol)
					PROXY_PROTOCOL=$2
					shift
					;;
				--invalid-cert-disconnect)
					INVALID_CERT_DISCO="Y"
					;;
				--invalid-cert-notify)
					INVALID_CERT_NOTIFY="Y"
					;;
				--db-type)
					DB_TYPE=$2
					shift
					;;
				--sqlguard-ip)
					COLLECTOR=$2
					shift
					;;
				--tenant-id)
					TENANT_ID=$2
					shift
					;;
				--override-server-ip)
					FORCE_SERVER_IP=1
					TAP_IP=$2
					PRIVATE_TAP_IP="127.0.0.1"
					shift
					;;
				--participate-in-load-balancing)
					PARTICIPATE_IN_LOAD_BALANCING=$2
					shift
					;;
				--sqlguard-cert-cn)
					SQLGUARD_CERT_CN=$2
					shift
					;;
				--svc-image)
					SVC_IMAGE=$2
					shift
					;;
				--svc-host)
					SVC_HOST=$2
					shift
					;;
				--svc-port-range)
					SVC_PORT_RANGE=$2
					shift
					;;
				--svc-host-user)
					SVC_HOST_USER=$2
					shift
					;;
				--repo-user)
					REPO_USER=$2
					shift
					;;
				--repo-pass)
					REPO_PASS=$2
					shift
					;;
				--state-file)
					STATE_FILE=$2
					shift
					;;
				--kill-after)
					KILL_AFTER=$2
					shift
					;;
				--envvar)
					ENVVARS="${ENVVARS} -e ${2} "
					shift
					;;
				--mount)
					# in the form volume:/mountpoint
					MNTSRC=`echo "${2}" | cut -d':' -f1`
					MNTDST=`echo "${2}" | cut -d':' -f2`
					if [ "$MNTSRC" = "" ] || [ "$MNTDST" = "" ] ; then
						echo "--mount needs source:/destination"
						exit 1
					fi
					MOUNTS="${MOUNTS} --mount type=bind,source=$MNTSRC,target=$MNTDST "
					shift
					;;
				--volume)
					# in the form volume:/mountpoint[:options]
					# volume needs to be a docker volume, not just a dir
					VOLARGS=${2}
					VOLSRC=`echo "${2}" | cut -d':' -f1`
					if [ "$VOLSRC" = "" ] ; then
						echo "--persistent needs Docker volume name"
						exit 1
					fi
					${LOCAL_DOCKER_CMD} volume ls | grep -w "$VOLSRC" >/dev/null 2>&1
					if [ $? -ne 0 ] ; then
						echo "--persistent Docker volume does not exist"
						exit 1
					fi
					MOUNTS="${MOUNTS} --volume $VOLARGS "
					shift
					;;
				--persistent)
					# volume needs to be a docker volume, not just a dir
					VOLSRC=${2}
					VOLDST=/persistent
					if [ "$VOLSRC" = "" ] ; then
						echo "--persistent needs Docker volume name"
						exit 1
					fi
					${LOCAL_DOCKER_CMD} volume ls | grep -w "$VOLSRC" >/dev/null 2>&1
					if [ $? -ne 0 ] ; then
						echo "--persistent Docker volume does not exist"
						exit 1
					fi
					MOUNTS="${MOUNTS} --volume $VOLSRC:$VOLDST:rw "
					shift
					;;
				*)
					\echo "Error: unrecognized argument $1"
					do_usage
					exit 1
					;;
			esac
		fi
		shift
		if developer_option_extra_shift $THIS_PARAM; then
			shift
		fi
	done
}

#get_container_ip()
#{
#	_CONTAINER=$1
#	_IP=`${REMOTE_DOCKER_CMD} inspect $_CONTAINER | grep "\"IPAddress\"" | sed -n '1p' | awk '{ print $2 }' | cut -d ',' -f1 | sed "s/\"//g"`
#	if [ "$_IP" != "" ]; then
#		echo $_IP
#	else
#		echo 0.0.0.0
#	fi
#}

validate_ip() {
	ERR_MSG=$1
	RESP=$2
	empty_ok=$3
	if [ $empty_ok -eq 0 ]; then
		if [ "$RESP" = "" ]; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		fi
	fi
	if print $RESP | grep "^[0-9.]*$" > /dev/null 2>&1; then
		# IPv4
		echo "IPv4 ($RESP)"
		if print $RESP | grep -v "^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$" > /dev/null 2>&1; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		else
			return 0
		fi
	elif print $RESP | grep ":" > /dev/null 2>&1; then
		# IPv6
		echo "IPv6 ($RESP)"
		if print $RESP | grep -v "^\([0-9a-fA-F]\{0,4\}:\)\{1,7\}[0-9a-fA-F]\{0,4\}$" > /dev/null 2>&1; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		elif [ `print $RESP | awk '{ print gsub(/:/, "") }'` -gt 7 ]; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		elif print $RESP | grep -v "[0-9a-fA-F]\{1,4\}$" > /dev/null 2>&1; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		elif print $RESP | grep ":::" > /dev/null 2>&1; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		elif [ `print $RESP | awk '{ print gsub(/::/, "") }'` -ge 2 ]; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		elif [ `print $RESP | awk '{ print gsub(/:/, "") }'` -lt 7 ]; then
			if print $RESP | grep -v "::"; then
				echo "$ERR_MSG \"$RESP\""
				return 1
			else 
				return 0
			fi
		else
			return 0
		fi
	else
		# DNS name
		echo "DNS ($RESP)"
		if print $RESP | grep "^-" > /dev/null 2>&1; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		elif print $RESP | grep "[.][0-9]*[.]" > /dev/null 2>&1; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		elif print $RESP | grep "[.]-" > /dev/null 2>&1; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		else
			return 0
		fi
	fi
}

validate_integer() {
	ERR_MSG=$1
	RESP=$2
	empty_ok=$3
	if [ $empty_ok -eq 0 ]; then
		if [ "$RESP" = "" ]; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		fi
	fi
	if print $RESP | grep "[^0-9]" > /dev/null 2>&1; then
		echo "$ERR_MSG \"$RESP\""
		return 1
	else
		return 0
	fi
}

validate_character() {
	ERR_MSG=$1
	RESP=$2
	VALID_CHARS=$3
	if [ "$RESP" = "" ] || [ "`print $RESP | wc -c | awk '{ gsub(/[ \t\n]+/, "", $0); printf $0; }'`" != "1" ]; then
		echo "$ERR_MSG \"$RESP\""
		return 1
	else
		if echo $VALID_CHARS | grep $RESP > /dev/null 2>&1; then
			return 0
		else
			echo "$ERR_MSG \"$RESP\""
			return 1
		fi
	fi
}

validate_string() {
	ERR_MSG=$1
	RESP=$2
	empty_ok=$3
	max_len=${4:-0}

	if [ $empty_ok -eq 0 ]; then
		if [ "$RESP" = "" ]; then
			echo "$ERR_MSG \"$RESP\""
			return 1
		fi
	fi
	if print $RESP | grep "[ 	]" > /dev/null 2>&1; then
		echo "$ERR_MSG \"$RESP\""
		return 1
	elif [ $max_len -ne 0 ]; then
		str_len=`print $RESP | wc -c`
		if [ $str_len -gt $max_len ]; then
			echo "$ERR_MSG \"$RESP\", longer than maximum length ${max_len}"
			return 1
		else
			return 0
		fi
	else
		return 0
	fi
}

validate_port_range() {
	ERR_MSG=$1
	RESP=$2
	if [ "$RESP" = "0" ] || [ "`echo $RESP | sed 's/[0-9][0-9]*-[0-9][0-9]*//'`" = "" ]; then
		return 0
	else
		echo "$ERR_MSG \"$RESP\""
		return 1
	fi
}

get_resp() {
	VAR=$1
	QUESTION=$2
	_TYPE=$3
	VALID_CHARS=$4
	max_str_len=${5:-0}

	eval "DEFAULT=\"\$$VAR\""
	VALID_CHARS="`print $VALID_CHARS | tr 'a-z' 'A-Z'`"
	RESP_OK=1
	# Separate questions by printing a newline each time
	println
	while [ $RESP_OK -ne 0 ]; do
		if [ "$DEFAULT" != "" ]; then
			case "$_TYPE" in
				password)
					print "$QUESTION[`echo $DEFAULT | sed 's/./X/g'`] "
					;;
				*)
					print "$QUESTION[$DEFAULT] "
					;;
			esac
		else
			print "$QUESTION"
		fi
		case "$_TYPE" in
			password)
				STTY_SAVE=`stty -g`
				stty -echo
				read RESP
				stty $STTY_SAVE
				echo
				;;
			*)
				read RESP
				;;
		esac
		RESP=`print $RESP | sed 's/\n//g'`
		if [ "$RESP" = "" ] && [ "$DEFAULT" != "" ]; then
			RESP=$DEFAULT
			RESP_OK=0
		elif [ "$RESP" = "" ] && [ "$DEFAULT" = "" ] && [ "$_TYPE" = "string_empty_ok" ]; then
			RESP_OK=0
		else
			case "$_TYPE" in
				ip)
					validate_ip "Invalid input" "$RESP" 0
					RESP_OK=$?
					;;
				ip_empty_ok)
					validate_ip "Invalid input" "$RESP" 1
					RESP_OK=$?
					;;
				integer_empty_ok)
					validate_integer "Invalid input" "$RESP" 1
					RESP_OK=$?
					;;
				integer)
					validate_integer "Invalid input" "$RESP" 0
					RESP_OK=$?
					;;
				character)
					RESP="`print $RESP | tr 'a-z' 'A-Z'`"
					validate_character "Invalid input" "$RESP" "$VALID_CHARS"
					RESP_OK=$?
					;;
				string)
					validate_string "Invalid input" "$RESP" 0 $max_str_len
					RESP_OK=$?
					;;
				password)
					validate_string "Invalid input" "$RESP" 0 $max_str_len
					RESP_OK=$?
					;;
				string_empty_ok)
					validate_string "Invalid input" "$RESP" 1 $max_str_len
					RESP_OK=$?
					;;
				portrange)
					validate_port_range "Invalid input" "$RESP"
					RESP_OK=$?
					;;
			esac
		fi
	done
	eval "$VAR=\"$RESP\""
}

# ------------------------------------------------
# Set up all configuration options

parse_cmd_line_args $@

if [ "$LB_SCRIPT" != "" ]; then
	if [ ! -f $LB_SCRIPT ]; then
		echo "LB interface script $LB_SCRIPT not found"
		do_usage
		exit 1
	fi
	. $LB_SCRIPT
	if [ $? -ne 0 ]; then
		echo "Error sourcing LB interface script $LB_SCRIPT"
		do_usage
		exit 1
	fi
else
	# Define stubs for the LB operations
	lb_import_state()    {
		:
	}
	lb_export_lb_state() {
		:
	}
	lb_add_one()         {
		:
	}
	lb_remove_one()      {
		:
	}
	lb_apply_config()    {
		:
	}
	lb_teardown_config() {
		:
	}
	lb_cleanup() {
		:
	}
fi

# Check for illegal combinations of parameters
developer_param_sanity

if [ "$STATE_FILE" = "" ]; then
	echo "--state-file must be specified"
	do_usage
	exit 1
fi

# TODO - Check all parameters for validity (files exist, tags are known, etc)

# Set defaults
if [ "$UUID" = "" ]; then
	UUID=$RANDOM_UUID
fi
if [ "$NUMBER_OF_CONTAINERS" = "" ]; then
	NUMBER_OF_CONTAINERS=1
fi
if [ "$NUM_WORKERS" = "" ]; then
	NUM_WORKERS=1
fi

mark_error() {
	ERROR=`expr $ERROR + $1`
}

print_valid_db_types() {
	echo "Valid DB types are \"oracle\", \"mssql\", \"sybase\", \"mongodb\", \"db2\", \"mysql\", \"memsql\", \"mariadb\", \"pgsql\", \"greenplumdb\", \"verticadb\", \"redis\", \"dynamodb\", \"el_search\", \"amazons3\", \"cockroach\", \"netezza\", \"hana\", \"snowflake\", \"trd\", \"milvus\", \"couch\""
}

valid_db_type() {
	VALID_TYPE=1
	if [ "$1" = "oracle" ] \
		|| [ "$1" = "mssql" ] \
		|| [ "$1" = "sybase" ] \
		|| [ "$1" = "mongodb" ] \
		|| [ "$1" = "db2" ] \
		|| [ "$1" = "mysql" ] \
		|| [ "$1" = "memsql" ] \
		|| [ "$1" = "mariadb" ] \
		|| [ "$1" = "pgsql" ] \
		|| [ "$1" = "greenplumdb" ] \
		|| [ "$1" = "verticadb" ] \
		|| [ "$1" = "redis" ] \
		|| [ "$1" = "dynamodb" ] \
		|| [ "$1" = "el_search" ] \
		|| [ "$1" = "bigquery" ] \
		|| [ "$1" = "amazons3" ] \
		|| [ "$1" = "cockroach" ] \
		|| [ "$1" = "netezza" ] \
		|| [ "$1" = "hana" ] \
		|| [ "$1" = "snowflake" ] \
		|| [ "$1" = "trd" ] \
		|| [ "$1" = "milvus" ] \
		|| [ "$1" = "couch" ] \
		|| [ "$1" = "neo4j" ] \
	; then
		VALID_TYPE=0
	fi
		# Currently unsupported marks
#		|| [ "$1" = "infx" ] \
#		|| [ "$1" = "teradata" ] \
#		|| [ "$1" = "netezza" ] \
#		|| [ "$1" = "hadoop" ] \
#		|| [ "$1" = "cassandra" ] \
#		|| [ "$1" = "asterdb" ] \
#		|| [ "$1" = "hana" ] \
#		|| [ "$1" = "hive" ] \
#		|| [ "$1" = "accumolo" ] \
#		|| [ "$1" = "impala" ] \
#		|| [ "$1" = "hue" ] \
#		|| [ "$1" = "webhdfs" ] \
#		|| [ "$1" = "solr" ] \
#		|| [ "$1" = "couchbase" ] \
	return $VALID_TYPE
}

# For non-interactive mode, verify we have enough defaults set to be
# able to continue
if [ $NI -ne 0 ] && ( [ "$ACTION" = "C" ] || [ "$ACTION" = "P" ] ); then
	if ! is_developer_cluster; then
		# Need to have valid parameters set, otherwise print
		# error and usage

		# Shouldn't happen, we set default of 1
		if [ "$NUMBER_OF_CONTAINERS" = "" ]; then
			echo "--svc-container-num must be specified"
			mark_error 1
		else
			validate_integer "Invalid value for --svc-container-num" "$NUMBER_OF_CONTAINERS" 0
			mark_error $?
		fi

		# Shouldn't happen, we set a default random one
		if [ "$UUID" = "" ]; then
			echo "--uuid must be specified"
			mark_error 1
		else
			validate_string "Invalid value for --uuid" "$UUID" 0
			mark_error $?
		fi

		# Can be set by collector, so not strictly required
		if [ "$DB_HOST" = "" ]; then
			:
#			echo "--db-host must be specified"
#			mark_error 1
		else
			validate_string "Invalid value for --db-host" "$DB_HOST" 0
			mark_error $?
			# TODO: verify IP

			# Can be set by collector, so not strictly required, but if you specify the host, we should have this
			if [ "$DB_PORT" = "" ]; then
				echo "--db-port must be specified"
				mark_error 1
			else
				validate_integer "Invalid value for --db-port" "$DB_PORT" 0
				mark_error $?
			fi

			# Can be set by collector, so not strictly required, but if you specify the host, we should have this
			if [ "$DB_TYPE" = "" ]; then
				echo "--db-type must be specified"
				mark_error 1
			else
				validate_string "Invalid value for --db-type" "$DB_TYPE" 0
				_ERROR=$?
				mark_error $_ERROR
				DB_TYPE=`echo $DB_TYPE | tr 'A-Z' 'a-z'`
				if [ $_ERROR -eq 0 ]; then
					if ! valid_db_type $DB_TYPE; then
						echo "Invalid value for --db-type \"$DB_TYPE\""
						print_valid_db_types
						mark_error 1
					fi
				fi
			fi
		fi

		validate_port_range "Invalid value for --svc-port-range" "$SVC_PORT_RANGE"
		mark_error $?

		# Shouldn't happen, we set default of 1
		if [ "$NUM_WORKERS" != "" ]; then
			validate_integer "Invalid value for --proxy-num-workers" "$NUM_WORKERS" 0
			mark_error $?
		fi

		if [ "$PROXY_PROTOCOL" != "0" ] && [ "$PROXY_PROTOCOL" != "1" ] && [ "$PROXY_PROTOCOL" != "2" ]; then
			echo "Invalid value for --proxy-protocol $PROXY_PROTOCOL"
			mark_error 1
		fi

		if [ "$TOKEN" != "" ]; then
			validate_string "Invalid value for --proxy-secret" "$TOKEN" 0
			mark_error $?
		fi

		if [ "$CSR_NAME" != "" ]; then
			validate_string "Invalid value for --proxy-csr-name" "$CSR_NAME" 0 64
			mark_error $?
			validate_string "Invalid value for --proxy-secret" "$TOKEN" 0
			mark_error $?
		fi
		if [ "$CSR_COUNTRY" != "" ]; then
			validate_string "Invalid value for --proxy-csr-country" "$CSR_COUNTRY" 0
			mark_error $?
		fi
		if [ "$CSR_PROVINCE" != "" ]; then
			validate_string "Invalid value for --proxy-csr-province" "$CSR_PROVINCE" 0
			mark_error $?
		fi
		if [ "$CSR_CITY" != "" ]; then
			validate_string "Invalid value for --proxy-csr-city" "$CSR_CITY" 0
			mark_error $?
		fi
		if [ "$CSR_ORGANIZATION" != "" ]; then
			validate_string "Invalid value for --proxy-csr-organization" "$CSR_ORGANIZATION" 0
			mark_error $?
		fi
		if [ "$CSR_KEYLENGTH" != "" ]; then
			validate_integer "Invalid value for --proxy-csr-keylength" "$CSR_KEYLENGTH" 0
			mark_error $?
		fi
		if [ "$CSR_KEYLENGTH" = "" ]; then
			CSR_KEYLENGTH=$DEFAULT_CSR_KEYLENGTH
		fi
		if [ $CSR_KEYLENGTH -lt 2048 ] || [ $CSR_KEYLENGTH -gt 8192 ]; then
			println "Key length must be between 2048 and 8192"
			mark_error 1
		fi

		developer_additional_containers_param_check

		if [ "$COLLECTOR" = "" ]; then
			echo "--sqlguard-ip must be specified"
			mark_error 1
		else
			validate_string "Invalid value for --sqlguard-ip" "$COLLECTOR" 0
			mark_error $?
			# TODO: verify IP
		fi

		if [ "$TENANT_ID" != "" ]; then
			validate_string "Invalid value for --tenant-id" "$TENANT_ID" 0
			mark_error $?
		fi

		if [ "$SVC_IMAGE" = "" ]; then
			echo "--svc-image must be specified"
			mark_error 1
		else
			validate_string "Invalid value for --svc-image" "$SVC_IMAGE" 0
			mark_error $?
		fi

		if [ "$PARTICIPATE_IN_LOAD_BALANCING" != "0" ]; then
			validate_character "Invalid value for --participate-in-load-balancing" "$PARTICIPATE_IN_LOAD_BALANCING" "0124"
			mark_error $?
		fi
	else
		if [ "$SVC_IMAGE" = "" ]; then
			echo "--svc-image must be specified"
			mark_error 1
		else
			validate_string "Invalid value for --svc-image" "$SVC_IMAGE" 0
			mark_error $?
		fi

		# Shouldn't happen, we set a default random one
		if [ "$UUID" = "" ]; then
			echo "--uuid must be specified"
			mark_error 1
		else
			validate_string "Invalid value for --uuid" "$UUID" 0
			mark_error $?
		fi

		# No collector, so must be set
		if [ "$DB_HOST" = "" ]; then
			echo "--db-host must be specified"
			mark_error 1
		else
			validate_string "Invalid value for --db-host" "$DB_HOST" 0
			mark_error $?
		fi

		validate_port_range "Invalid value for --svc-port-range" "$SVC_PORT_RANGE"
		mark_error $?

		# No collector, so must be set
		if [ "$DB_PORT" = "" ]; then
			echo "--db-port must be specified"
			mark_error 1
		else
			validate_integer "Invalid value for --db-port" "$DB_PORT" 0
			mark_error $?
		fi
	fi
fi

if [ $NI -ne 0 ] && [ "$ACTION" = "U" ]; then
	if ! is_developer_cluster; then
		# Need to have valid parameters set, otherwise print
		# error and usage
		if [ "$DB_HOST" != "" ]; then
			echo "--db-host not needed during upgrade"
		fi
		if [ "$DB_PORT" != "" ]; then
			echo "--db-port not needed during upgrade"
		fi
		if [ "$TOKEN" != "" ]; then
			echo "--proxy-secret not needed during upgrade"
		fi
		if [ "$CSR_NAME" != "" ]; then
			echo "--proxy-csr-name not needed during upgrade"
		fi
		if [ "$CSR_COUNTRY" != "" ]; then
			echo "--proxy-csr-country not needed during upgrade"
		fi
		if [ "$CSR_PROVINCE" != "" ]; then
			echo "--proxy-csr-province not needed during upgrade"
		fi
		if [ "$CSR_CITY" != "" ]; then
			echo "--proxy-csr-city not needed during upgrade"
		fi
		if [ "$CSR_ORGANIZATION" != "" ]; then
			echo "--proxy-csr-organization not needed during upgrade"
		fi
		if [ "$DB_TYPE" != "" ]; then
			echo "--db-type not needed during upgrade"
		fi
		if [ "$SVC_IMAGE" = "" ]; then
			echo "--svc-image must be specified"
			mark_error 1
		else
			validate_string "Invalid value for --svc-image" "$SVC_IMAGE" 0
			mark_error $?
		fi
		if [ "$KILL_AFTER" != "" ]; then
			validate_integer "Invalid value for --kill-after" "$KILL_AFTER" 0
			mark_error $?
		fi
	else
		echo "Cannot upgrade a developer cluster"
		mark_error 1
	fi
fi

if [ $NI -ne 0 ] && [ "$ACTION" = "D" ]; then
	# Need to have valid parameters set, otherwise print
	# error and usage
	if [ "$DB_HOST" != "" ]; then
		echo "--db-host not needed during delete"
	fi
	if [ "$DB_PORT" != "" ]; then
		echo "--db-port not needed during delete"
	fi
	if [ "$TOKEN" != "" ]; then
		echo "--proxy-secret not needed during delete"
	fi
	if [ "$CSR_NAME" != "" ]; then
		echo "--proxy-csr-name not needed during delete"
	fi
	if [ "$CSR_COUNTRY" != "" ]; then
		echo "--proxy-csr-country not needed during delete"
	fi
	if [ "$CSR_PROVINCE" != "" ]; then
		echo "--proxy-csr-province not needed during delete"
	fi
	if [ "$CSR_CITY" != "" ]; then
		echo "--proxy-csr-city not needed during delete"
	fi
	if [ "$CSR_ORGANIZATION" != "" ]; then
		echo "--proxy-csr-organization not needed during delete"
	fi
	if [ "$DB_TYPE" != "" ]; then
		echo "--db-type not needed during delete"
	fi
	if [ "$SVC_IMAGE" != "" ]; then
		echo "--svc-image not needed during delete"
	fi
	if [ "$KILL_AFTER" != "" ]; then
		validate_integer "Invalid value for --kill-after" "$KILL_AFTER" 0
		mark_error $?
	fi
fi

if [ $NI -ne 0 ] && [ "$ACTION" = "R" ]; then
	if [ "$LB_SCRIPT" = "" ]; then
		echo "--lb-script must be specified to remove interception"
		mark_error 1
	fi
fi

if [ $NI -ne 0 ] && [ "$ACTION" = "E" ]; then
	if [ "$LB_SCRIPT" = "" ]; then
		echo "--lb-script must be specified to enable interception"
		mark_error 1
	fi
fi

if [ $NI -ne 0 ] && [ "$ACTION" = "" ]; then
	echo "One of --c, --r, --e, --u, --d, or --z must be specified with --ni"
	mark_error 1
fi

# Z does not have required parameters

# If we have an error in processing up to this point, print usage and exit
if [ $ERROR -ne 0 ]; then
	do_usage
	exit 1
fi

print_ni_param() {
	PARAM=$1
	VALUE=$2

	# Only print parameters when there is a value
	if [ "$VALUE" != "" ]; then
		echo "Non-interactive parameter: $PARAM $VALUE"
	fi
}
	
if [ $NI -eq 0 ]; then
	# Ask for user input for required settings
	if [ "$LB_SCRIPT" != "" ]; then
		get_resp \
			"ACTION" \
			"Would you like to \n\t(c)reate a new cluster\n\t(p)rint env vars without creating cluster\n\t(r)emove interception from a cluster\n\t(e)nable interception with a cluster\n\t(u)pgrade an existing cluster\n\t(d)elete a cluster\n\tremove (z)ombies\n? " \
			"character" \
			"CPREUDZ"
	else
		echo "Load-balancer script integration not specified, some functionality may be limited"
		get_resp \
			"ACTION" \
			"Would you like to \n\t(c)reate a new cluster\n\t(p)rint env vars without creating cluster\n\t(u)pgrade an existing cluster\n\t(d)elete a cluster\n\tremove (z)ombies\n? " \
			"character" \
			"CPUDZ"
	fi
	print_ni_param "--`echo $ACTION | tr 'A-Z' 'a-z'`"
	if ( [ "$ACTION" = "C" ] || [ "$ACTION" = "P" ] ); then
		if [ -f $STATE_FILE ]; then
			echo "$STATE_FILE already exists.  If you wish to replace the file, please delete and run again"
			do_usage
			exit 1
		fi
		if [ "$ACTION" = "C" ]; then
			if ! is_developer_cluster; then
				echo
				echo "==============="
				echo "Creating service containers for Guardium External S-TAP"
			else
				echo "Creating service containers for Developer Cluster"
			fi
		else
			if ! is_developer_cluster; then
				echo
				echo "==============="
				echo "Printing service container env vars for Guardium External S-TAP"
			else
				echo "Printing service container env vars for Developer Cluster"
			fi
		fi
		echo
		if [ "$ACTION" = "C" ]; then
			get_resp \
				"SVC_HOST" \
				"What host do you want to use to host the service containers? " \
				"string"
			print_ni_param "--svc-host" "$SVC_HOST"
			get_resp \
				"SVC_PORT_RANGE" \
				"What is the port range for the exported service port? (0 means the ephemeral range on the service host) " \
				"portrange"
			print_ni_param "--svc-port-range" "$SVC_PORT_RANGE"
			get_resp \
				"SVC_HOST_USER" \
				"What user will be logging in to the host to start the service containers? " \
				"string"
			print_ni_param "--svc-host-user" "$SVC_HOST_USER"
			get_resp \
				"SVC_IMAGE" \
				"Enter the hash or tag for the service container image: " \
				"string"
			print_ni_param "--svc-image" "$SVC_IMAGE"
			get_resp \
				"REPO_USER" \
				"What is the username to be used if login is required to pull the service container image? (optional) " \
				"string_empty_ok"
			if [ "$REPO_USER" != "" ]; then
				print_ni_param "--repo-user" "$REPO_USER"
				get_resp \
					"REPO_PASS" \
					"What is the password for $REPO_USER? " \
					"password"
				print_ni_param "--repo-pass" "`echo $REPO_PASS | sed 's/./X/g'`"
			fi
		fi
		get_resp \
			"NUMBER_OF_CONTAINERS" \
			"How many service containers would you like to create? " \
			"integer"
		print_ni_param "--svc-container-num" "$NUMBER_OF_CONTAINERS"
		get_resp \
			"UUID" \
			"Please enter a UUID for this group: " \
			"string"
		print_ni_param "--uuid" "$UUID"
		if ! is_developer_cluster; then
			get_resp \
				"NUM_WORKERS" \
				"Enter the number of workers for each service container of Guardium External S-TAP: " \
				"integer"
			print_ni_param "--proxy-num-workers" "$NUM_WORKERS"
			get_resp \
				"DB_HOST" \
				"Enter the hostname or IP to which the DB the Guardium External S-TAP group will be relaying traffic: (optional) " \
				"string_empty_ok"
			print_ni_param "--db-host" "$DB_HOST"
			if [ "$DB_HOST" != "" ]; then
				print_valid_db_types
				get_resp \
					"DB_TYPE" \
					"Enter the type of database for the DB host: " \
					"string"
				DB_TYPE=`echo $DB_TYPE | tr 'A-Z' 'a-z'`
				while ! valid_db_type $DB_TYPE; do
					echo "DB type \"$DB_TYPE\" not supported."
					print_valid_db_types
					get_resp \
						"DB_TYPE" \
						"Enter the type of database for the DB host: " \
						"string"
					DB_TYPE=`echo $DB_TYPE | tr 'A-Z' 'a-z'`
				done
				print_ni_param "--db-type" "$DB_TYPE"
				get_resp \
					"DB_PORT" \
					"Enter the port for the DB to which the Guardium External S-TAP group will be relaying traffic: " \
					"integer"
				print_ni_param "--db-port" "$DB_PORT"
			else
				echo
				echo "---------------"
				echo "No inspection engine will be created for now and the service instance will not relay traffic."
				echo "Please remember to create one from the collector GUI."
				echo "---------------"
				echo
			fi
			get_resp \
				"TAP_IP" \
				"Enter an IP to override and force the server IP to be reported as (optional and uncommon, leave blank if not needed): " \
				"ip_empty_ok"
			if [ "${TAP_IP}" != "" ] && [ "${TAP_IP}" != "NULL" ]; then
				print_ni_param "--override-server-ip" "$TAP_IP"
				PRIVATE_TAP_IP="127.0.0.1"
				FORCE_SERVER_IP=1
			fi
			get_resp \
				"PROXY_PROTOCOL" \
				"If proxy protocol version 1 is enabled for the DB traffic, enter 1, if proxy protocol version 2 is enabled for the DB traffic, enter 2, otherwise enter 0: " \
				"character" \
				"012"
			print_ni_param "--proxy-protocol" "$PROXY_PROTOCOL"
			get_resp \
				"INVALID_CERT_DISCO" \
				"Do you wish to disconnect the clients if the DB server certificate cannot be verified? (y/n) " \
				"character" \
				"YN"
			if [ $INVALID_CERT_DISCO = "Y" ]; then
				print_ni_param "--invalid-cert-disconnect"
			fi
			get_resp \
				"INVALID_CERT_NOTIFY" \
				"Do you wish to log an error message if the DB server certificate cannot be verified? (y/n) " \
				"character" \
				"YN"
			if [ $INVALID_CERT_NOTIFY = "Y" ]; then
				print_ni_param "--invalid-cert-notify"
			fi

			get_resp \
				"TOKEN" \
				"If traffic is encrypted and you are generating CSRs on the collector and signing them separately,\nenter the secret token which will be used to retrieve the key and signed certificate from the Guardium Collector: " \
				"string_empty_ok"
			print_ni_param "--proxy-secret" "$TOKEN"

			if [ "$TOKEN" = "" ]; then
				get_resp \
					"CSR_NAME" \
					"If traffic is encrypted and you have a signing certificate stored on the collector to automatically\nsign CSRs generated by External S-TAP, enter the Name field for the CSR's CN: " \
					"string_empty_ok" \
					"" \
					64
				print_ni_param "--proxy-csr-name" "$CSR_NAME"

				if [ "$CSR_NAME" != "" ]; then
					get_resp \
						"CSR_COUNTRY" \
						"Enter the Country field for the CSR's CN: " \
						"string_empty_ok"
					print_ni_param "--proxy-csr-country" "$CSR_COUNTRY"
					get_resp \
						"CSR_PROVINCE" \
						"Enter the Province field for the CSR's CN: " \
						"string_empty_ok"
					print_ni_param "--proxy-csr-province" "$CSR_PROVINCE"
					get_resp \
						"CSR_CITY" \
						"Enter the City field for the CSR's CN: " \
						"string_empty_ok"
					print_ni_param "--proxy-csr-city" "$CSR_CITY"
					get_resp \
						"CSR_ORGANIZATION" \
						"Enter the Organization field for the CSR's CN: " \
						"string_empty_ok"
					print_ni_param "--proxy-csr-organization" "$CSR_ORGANIZATION"
					get_resp \
						"CSR_KEYLENGTH" \
						"Enter the length for the CSRs private key: " \
						"integer"
					while [ $CSR_KEYLENGTH -lt 2048 ] || [ $CSR_KEYLENGTH -gt 8192 ]; do
						println "Key length must be between 2048 and 8192"
						get_resp \
							"CSR_KEYLENGTH" \
							"Enter the length for the CSRs private key: " \
							"integer"
					done
					print_ni_param "--proxy-csr-keylength" "$CSR_KEYLENGTH"
					get_resp \
						"TOKEN" \
						"Signing a CSR on the collector requires a token to authorize signing.\nPlease enter the secret token which will be used to authorize signing on the Guardium Collector: " \
						"string"
					print_ni_param "--proxy-secret" "$TOKEN"
				else
					println
					println "External S-TAP will not be intercepting TLS traffic"
					println
				fi
			fi

			if [ "$GSERV_IP" = "" ]; then
				if ! developer_have_additional_containers; then
					get_resp \
						"COLLECTOR" \
						"Enter the hostname or IP of the Guardium Collector: " \
						"string"
					print_ni_param "--sqlguard-ip" "$COLLECTOR"
					get_resp \
						"TENANT_ID" \
						"Enter the tenant_id for the deployment: " \
						"string_empty_ok"
					print_ni_param "--tenant-id" "$TENANT_ID"
					get_resp \
						"PARTICIPATE_IN_LOAD_BALANCING" \
						"Participate in load balancing or failover? 0: failover/no lb, 1) split, 2) redundancy, 3) not allowed, 4) threaded: " \
						"character" \
						"0124"
					print_ni_param "--participate-in-load-balancing" "$PARTICIPATE_IN_LOAD_BALANCING"
					get_resp \
						"SQLGUARD_CERT_CN" \
						"Enter the CN to match when verifying the Guardium Collector's Certificate (blank to disable verification): "\
						"string_empty_ok"
					print_ni_param "--sqlguard-cert-cn" "$SQLGUARD_CERT_CN"
				else
					developer_note_additional_containers
				fi
			fi
		else
			developer_cluster_interactive_setup
		fi
	elif [ "$ACTION" = "U" ]; then
		echo
		echo "==============="
		echo "Upgrading service containers for Guardium External S-TAP"
		echo
		get_resp \
			"SVC_HOST_USER" \
			"What user will be logging in to the host to manage the service containers? " \
			"string"
		print_ni_param "--svc-host-user" "$SVC_HOST_USER"
		get_resp \
			"SVC_IMAGE" \
			"Enter the hash or tag for the service container image: " \
			"string"
		get_resp \
			"REPO_USER" \
			"What is the username to be used if login is required to pull the service container image? (optional) " \
			"string_empty_ok"
		if [ "$REPO_USER" != "" ]; then
			print_ni_param "--repo-user" "$REPO_USER"
			get_resp \
				"REPO_PASS" \
				"What is the password for $REPO_USER? " \
				"password"
			print_ni_param "--repo-pass" "`echo $REPO_PASS | sed 's/./X/g'`"
		fi
		print_ni_param "--svc-image" "$SVC_IMAGE"
		get_resp \
			"KILL_AFTER" \
			"Enter the number of seconds to wait before forcefully stopping the old containers (0 is wait 30s, but don't forcefully stop): " \
			"integer"
		print_ni_param "--kill-after" "$KILL_AFTER"
	elif [ "$ACTION" = "D" ]; then
		echo
		echo "==============="
		echo "Deleting service containers for Guardium External S-TAP"
		echo
		get_resp \
			"SVC_HOST_USER" \
			"What user will be logging in to the host to stop the service containers? " \
			"string"
		print_ni_param "--svc-host-user" "$SVC_HOST_USER"
		get_resp \
			"KILL_AFTER" \
			"Enter the number of seconds to wait before forcefully stopping the old containers (0 is wait 30s, but don't forcefully stop): " \
			"integer"
		print_ni_param "--kill-after" "$KILL_AFTER"
	elif [ "$ACTION" = "Z" ]; then
		echo
		echo "==============="
		echo "Cleaning up zombie service containers for Guardium External S-TAP"
		echo
		get_resp \
			"SVC_HOST_USER" \
			"What user will be logging in to the host to stop the service containers? " \
			"string"
		print_ni_param "--svc-host-user" "$SVC_HOST_USER"
		get_resp \
			"KILL_AFTER" \
			"Enter the number of seconds to wait before forcefully stopping the old containers (0 is wait 30s, but don't forcefully stop): " \
			"integer"
		print_ni_param "--kill-after" "$KILL_AFTER"
	fi
	echo "==============="
	echo
	echo
else
	:
fi


if [ "$ACTION" = "C" ] || [ "$ACTION" = "D" ] || [ "$ACTION" = "U" ] || [ "$ACTION" = "Z" ]; then
	USING_PODMAN=0
	USING_DOCKER=0
	# Verify accessibility of service container deployment machines
	for HOST in `echo $SVC_HOST | sed 's/,/ /g'`; do
		ssh ${SVC_HOST_USER}@${HOST} echo "Login to $HOST successful"
		if [ $? -ne 0 ]; then
			echo "Couldn't login to $HOST as $SVC_HOST_USER!"
			do_usage
			exit 1
		fi
		ssh ${SVC_HOST_USER}@${HOST} type podman >/dev/null 2>&1
		if [ $? -eq 0 ]; then
			USING_PODMAN=1
		else
			USING_DOCKER=1
		fi
	done
	if [ $USING_PODMAN -eq 1 ] && [ $USING_DOCKER -eq 1 ]; then
		echo "Some hosts are using docker and some are using podman.  All hosts must use the same interface."
		exit 1
	fi
	if [ $USING_PODMAN -eq 1 ]; then
		REMOTE_DOCKER_CMD="podman"
		SVC_HOST_EXPORT_ANY_IP=""
	fi
fi

if [ "$ACTION" = "C" ] || [ "$ACTION" = "P" ]; then
	if [ -f $STATE_FILE ]; then
		echo "$STATE_FILE already exists.  If you wish to replace the file, please delete and run again"
		do_usage
		exit 1
	fi
	touch $STATE_FILE
	if [ ! -f $STATE_FILE ]; then
		echo "Could not create $STATE_FILE!"
		do_usage
		exit 1
	fi
	rm -f $STATE_FILE

	if [ "$ACTION" = "C" ]; then
		# If a gserv container is being created as well, use this as the collector for the
		# Guardium External S-TAP containers
		developer_additional_containers_creation
	fi
fi

graceful_terminate() {
	DHOST=$1
	DNAME=$2
	PROCESS_TAG=$3
	ssh ${SVC_HOST_USER}@${DHOST} ${REMOTE_DOCKER_CMD} exec ${DNAME}${PROCESS_TAG} bash -c \"if [ -f /etc/gp/.gp.SHUTDOWN ]\; then exit 0\; else exit 1\; fi\"
	if [ $? -eq 0 ]; then
		ssh ${SVC_HOST_USER}@${DHOST} ${REMOTE_DOCKER_CMD} rm -f ${DNAME}${PROCESS_TAG}
	else
		if [ $KILL_AFTER -gt 0 ]; then
			WAITING=$KILL_AFTER
			while [ $WAITING -gt 0 ]; do
				sleep 1
				ssh ${SVC_HOST_USER}@${DHOST} ${REMOTE_DOCKER_CMD} exec ${DNAME}${PROCESS_TAG} bash -c \"if [ -f /etc/gp/.gp.SHUTDOWN ]\; then exit 0\; else exit 1\; fi\"
				if [ $? -eq 0 ]; then
					ssh ${SVC_HOST_USER}@${DHOST} ${REMOTE_DOCKER_CMD} rm -f ${DNAME}${PROCESS_TAG}
					break
				else
					WAITING=`expr $WAITING - 1`
				fi
			done
			if [ $WAITING -eq 0 ]; then
				echo "Forcing stop of old container ${DNAME}${PROCESS_TAG} on host $DHOST"
				ssh ${SVC_HOST_USER}@${DHOST} ${REMOTE_DOCKER_CMD} rm -f ${DNAME}${PROCESS_TAG}
			fi
		else
			WAITING=30
			while [ $WAITING -gt 0 ]; do
				sleep 1
				ssh ${SVC_HOST_USER}@${DHOST} ${REMOTE_DOCKER_CMD} exec ${DNAME}${PROCESS_TAG} bash -c \"if [ -f /etc/gp/.gp.SHUTDOWN ]\; then exit 0\; else exit 1\; fi\"
				if [ $? -eq 0 ]; then
					ssh ${SVC_HOST_USER}@${DHOST} ${REMOTE_DOCKER_CMD} rm -f ${DNAME}${PROCESS_TAG}
					break
				else
					WAITING=`expr $WAITING - 1`
				fi
			done
			if [ $WAITING -eq 0 ]; then
				if [ "${PROCESS_TAG}" != "" ]; then
					# If the PROCESS_TAG is NULL, then we're not able to rename the container, likely because
					# it's already a zombie
					ssh ${SVC_HOST_USER}@${DHOST} ${REMOTE_DOCKER_CMD} rename ${DNAME}${PROCESS_TAG} ${DNAME}-zombie-$$
					ZOMBIES="${ZOMBIES} ZOMBIE_STATE=${DHOST},${DNAME}-zombie-$$"
					ZNAME=${DNAME}-zombie-$$
				else
					ZOMBIES="${ZOMBIES} ZOMBIE_STATE=${DHOST},${DNAME}"
					ZNAME=${DNAME}
				fi
				WARNINGS="$WARNINGS\n\
Old container ${ZNAME} still running on host $DHOST\n\
Please close open connections using this container and remove when desired.\n\
When the file /etc/gp/.gp.SHUTDOWN exists in the container, there are no\n\
open connections that would be terminated by removal.\n\
\n"
			fi
		fi
	fi
}

add_zombies_to_file() {
	FILE=$1
	if echo $ZOMBIES | grep -q ZOMBIE_STATE; then
		for ZOMBIE in $ZOMBIES; do
			echo $ZOMBIE >> $FILE
		done
		WARNINGS="$WARNINGS \
\
Zombies left tracked in $FILE"
	fi
}

upgrade_abort() {
	for ENTRY in $UPGRADING; do
		NAME=`echo $ENTRY | cut -d',' -f1`
		HOST=`echo $ENTRY | cut -d',' -f2`
		HASHES=`ssh ${SVC_HOST_USER}@${HOST} "${REMOTE_DOCKER_CMD} ps -qf name=$NAME --no-trunc"`
		HASH_COUNT=`echo "$HASHES" | wc -l | awk '{ gsub(/[ \t\n]+/, "", $0); printf "$0"; }'`
		if [ $HASH_COUNT -eq 1 ]; then
			echo "Setting naming of $HASHES back to $NAME"
			ssh ${SVC_HOST_USER}@${HOST} "${REMOTE_DOCKER_CMD} rename $HASHES $NAME"
		else
			echo "Multiple entries found for $NAME"
			echo "$HASHES"
			echo "Leaving as-is"
		fi
	done
	add_zombies_to_file $STATE_FILE
}

find_available_port_in_range() {
	INSTANCE_HOST=$1
	SVC_HOST_USER=$2
	RANGE=$3
	LOW=`echo $RANGE | cut -d'-' -f1`
	HIGH=`echo $RANGE | cut -d'-' -f2`
	if [ "$RANGE" = "0" ]; then
		# use host's ephemeral range
		RANGE=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} "cat /proc/sys/net/ipv4/ip_local_port_range" < /dev/null`
		LOW=`echo $RANGE | awk '{ print $1 }'`
		HIGH=`echo $RANGE | awk '{ print $2 }'`
	fi
	# Yes, we will prevent collisions between TVPv4 and TCPv6 sockets.  This is because docker tends to listen on TCPv6
	IN_USE=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} "netstat --tcp -anl | sed -n '3,\\\$p' | awk '{ print \\\$4 }' | sed 's/.*://' | sort -n" < /dev/null`
	if [ $LOW -eq 0 ] || [ $HIGH -eq 0 ]; then
		echo 0
		return 0
	fi
	for EXPORTED_PORT in $(seq $LOW $HIGH); do
		if echo "$IN_USE" | grep "^$EXPORTED_PORT$" 2>&1 > /dev/null; then
			:
		else
			echo $EXPORTED_PORT
			return 1
		fi
	done

	# No free port found
	echo 0
	return 0
}

get_config_from_container() {
	INSTANCE_HOST=$1
	INSTANCE_NAME=$2

	INSTANCE_ENV=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} exec $INSTANCE_NAME env`
	if [ $? -eq 0 ]; then
		TAP_IP=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_TAP_IP | sed "s/.*=\(.*\)/\1/"`
		PRIVATE_TAP_IP=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_TAP_PRIVATE_TAP_IP | sed "s/.*=\(.*\)/\1/"`
		FORCE_SERVER_IP=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_TAP_FORCE_SERVER_IP | sed "s/.*=\(.*\)/\1/"`
		NUMBER_OF_CONTAINERS=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_GROUP_MEMBER_COUNT | sed "s/.*=\(.*\)/\1/"`
		PROXY_PROTOCOL=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_PROXY_PROTOCOL | sed "s/.*=\(.*\)/\1/"`
		INVALID_CERT_DISCO=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE | sed "s/.*=\(.*\)/\1/"`
		INVALID_CERT_NOTIFY=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE | sed "s/.*=\(.*\)/\1/"`
		UUID=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_GROUP_UUID | sed "s/.*=\(.*\)/\1/"`
		DB_HOST=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_DB_HOST | sed "s/.*=\(.*\)/\1/"`
		DB_PORT=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_DB_0_REAL_DB_PORT | sed "s/.*=\(.*\)/\1/"`
		DB_TYPE=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_DB_0_DB_TYPE | sed "s/.*=\(.*\)/\1/"`
		LISTEN_PORT=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_LISTEN_PORT | sed "s/.*=\(.*\)/\1/"`
		DEBUG=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_DEBUG | sed "s/.*=\(.*\)/\1/"`
		NUM_WORKERS=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_NUM_WORKERS | sed "s/.*=\(.*\)/\1/"`

		TOKEN=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_SECRET | sed "s/.*=\(.*\)/\1/"`

		CSR_NAME=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_CSR_NAME | sed "s/.*=\(.*\)/\1/"`
		CSR_COUNTRY=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_CSR_COUNTRY | sed "s/.*=\(.*\)/\1/"`
		CSR_PROVINCE=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_CSR_PROVINCE | sed "s/.*=\(.*\)/\1/"`
		CSR_CITY=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_CSR_CITY | sed "s/.*=\(.*\)/\1/"`
		CSR_ORGANIZATION=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_CSR_ORGANIZATION | sed "s/.*=\(.*\)/\1/"`
		CSR_KEYLENGTH=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PROXY_CSR_KEYLENGTH | sed "s/.*=\(.*\)/\1/"`

		COLLECTOR0=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_0_SQLGUARD_IP | sed "s/.*=\(.*\)/\1/"`
		COLLECTOR1=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_1_SQLGUARD_IP | sed "s/.*=\(.*\)/\1/"`
		COLLECTOR2=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_2_SQLGUARD_IP | sed "s/.*=\(.*\)/\1/"`
		COLLECTOR3=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_3_SQLGUARD_IP | sed "s/.*=\(.*\)/\1/"`
		COLLECTOR4=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_4_SQLGUARD_IP | sed "s/.*=\(.*\)/\1/"`
		COLLECTOR5=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_5_SQLGUARD_IP | sed "s/.*=\(.*\)/\1/"`
		COLLECTOR6=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_6_SQLGUARD_IP | sed "s/.*=\(.*\)/\1/"`
		COLLECTOR7=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_7_SQLGUARD_IP | sed "s/.*=\(.*\)/\1/"`
		COLLECTOR8=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_8_SQLGUARD_IP | sed "s/.*=\(.*\)/\1/"`
		COLLECTOR9=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_9_SQLGUARD_IP | sed "s/.*=\(.*\)/\1/"`

		TENANT_ID=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_TAP_TENANT_ID | sed "s/.*=\(.*\)/\1/"`

		SQLGUARD_CERT_CN=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_SQLGUARD_CERT_CN | sed "s/.*=\(.*\)/\1/"`
		PARTICIPATE_IN_LOAD_BALANCING=`echo "$INSTANCE_ENV" | grep STAP_CONFIG_PARTICIPATE_IN_LOAD_BALANCING | sed "s/.*=\(.*\)/\1/"`

		STAP_CONFIG_TAP_TAP_IP="${STAP_CONFIG_TAP_TAP_IP_FMT}${TAP_IP}"
		STAP_CONFIG_TAP_PRIVATE_TAP_IP="${STAP_CONFIG_TAP_PRIVATE_TAP_IP_FMT}${PRIVATE_TAP_IP}"
		STAP_CONFIG_TAP_FORCE_SERVER_IP="${STAP_CONFIG_TAP_FORCE_SERVER_IP_FMT}${FORCE_SERVER_IP}"
		STAP_CONFIG_PROXY_GROUP_MEMBER_COUNT="${STAP_CONFIG_PROXY_GROUP_MEMBER_COUNT_FMT}${NUMBER_OF_CONTAINERS}"
		STAP_CONFIG_PROXY_GROUP_UUID="${STAP_CONFIG_PROXY_GROUP_UUID_FMT}${UUID}"
		if [ "${DB_HOST}" != "" ]; then
			STAP_CONFIG_PROXY_DB_HOST="${STAP_CONFIG_PROXY_DB_HOST_FMT}${DB_HOST}"
		fi
		if [ "${DB_PORT}" != "" ]; then
			STAP_CONFIG_DB_0_REAL_DB_PORT="${STAP_CONFIG_DB_0_REAL_DB_PORT_FMT}${DB_PORT}"
		fi
		if [ "${DB_TYPE}" != "" ]; then
			STAP_CONFIG_DB_0_DB_TYPE="${STAP_CONFIG_DB_0_DB_TYPE_FMT}${DB_TYPE}"
		fi
		STAP_CONFIG_PROXY_LISTEN_PORT="${STAP_CONFIG_PROXY_LISTEN_PORT_FMT}${LISTEN_PORT}"
		STAP_CONFIG_PROXY_DEBUG="${STAP_CONFIG_PROXY_DEBUG_FMT}${DEBUG}"
		STAP_CONFIG_PROXY_NUM_WORKERS="${STAP_CONFIG_PROXY_NUM_WORKERS_FMT}${NUM_WORKERS}"
		STAP_CONFIG_PROXY_PROXY_PROTOCOL="${STAP_CONFIG_PROXY_PROXY_PROTOCOL_FMT}${PROXY_PROTOCOL}"
		STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE="${STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE_FMT}${INVALID_CERT_DISCO}"
		STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE="${STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE_FMT}${INVALID_CERT_NOTIFY}"

		STAP_CONFIG_PROXY_SECRET="${STAP_CONFIG_PROXY_SECRET_FMT}${TOKEN}"

		STAP_CONFIG_PROXY_CSR_NAME="${STAP_CONFIG_PROXY_CSR_NAME_FMT}${CSR_NAME}"
		STAP_CONFIG_PROXY_CSR_COUNTRY="${STAP_CONFIG_PROXY_CSR_COUNTRY_FMT}${CSR_COUNTRY}"
		STAP_CONFIG_PROXY_CSR_PROVINCE="${STAP_CONFIG_PROXY_CSR_PROVINCE_FMT}${CSR_PROVINCE}"
		STAP_CONFIG_PROXY_CSR_CITY="${STAP_CONFIG_PROXY_CSR_CITY_FMT}${CSR_CITY}"
		STAP_CONFIG_PROXY_CSR_ORGANIZATION="${STAP_CONFIG_PROXY_CSR_ORGANIZATION_FMT}${CSR_ORGANIZATION}"
		STAP_CONFIG_PROXY_CSR_KEYLENGTH="${STAP_CONFIG_PROXY_CSR_KEYLENGTH_FMT}${CSR_KEYLENGTH}"

		SQLGUARD_PARAMS=
		if [ "$COLLECTOR0" != "" ]; then
			SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}0${STAP_CONFIG_SQLGUARD_IP_FMT}${COLLECTOR0} "
		fi
		if [ "$COLLECTOR1" != "" ]; then
			SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}1${STAP_CONFIG_SQLGUARD_IP_FMT}${COLLECTOR1} "
		fi
		if [ "$COLLECTOR2" != "" ]; then
			SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}2${STAP_CONFIG_SQLGUARD_IP_FMT}${COLLECTOR2} "
		fi
		if [ "$COLLECTOR3" != "" ]; then
			SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}3${STAP_CONFIG_SQLGUARD_IP_FMT}${COLLECTOR3} "
		fi
		if [ "$COLLECTOR4" != "" ]; then
			SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}4${STAP_CONFIG_SQLGUARD_IP_FMT}${COLLECTOR4} "
		fi
		if [ "$COLLECTOR5" != "" ]; then
			SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}5${STAP_CONFIG_SQLGUARD_IP_FMT}${COLLECTOR5} "
		fi
		if [ "$COLLECTOR6" != "" ]; then
			SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}6${STAP_CONFIG_SQLGUARD_IP_FMT}${COLLECTOR6} "
		fi
		if [ "$COLLECTOR7" != "" ]; then
			SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}7${STAP_CONFIG_SQLGUARD_IP_FMT}${COLLECTOR7} "
		fi
		if [ "$COLLECTOR8" != "" ]; then
			SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}8${STAP_CONFIG_SQLGUARD_IP_FMT}${COLLECTOR8} "
		fi
		if [ "$COLLECTOR9" != "" ]; then
			SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}9${STAP_CONFIG_SQLGUARD_IP_FMT}${COLLECTOR9} "
		fi

		STAP_CONFIG_TAP_TENANT_ID=""
		if [ "${TENANT_ID}" != "" ]; then
			STAP_CONFIG_TAP_TENANT_ID="${STAP_CONFIG_TAP_TENANT_ID_FMT}${TENANT_ID}"
		fi

		STAP_CONFIG_GUARDIUM_CA_PATH=""
		STAP_CONFIG_SQLGUARD_CERT_CN=""
		if [ "${SQLGUARD_CERT_CN}" != "" ]; then
			STAP_CONFIG_SQLGUARD_CERT_CN="${STAP_CONFIG_SQLGUARD_CERT_CN_FMT}${SQLGUARD_CERT_CN}"
			STAP_CONFIG_GUARDIUM_CA_PATH="${STAP_CONFIG_GUARDIUM_CA_PATH_FMT}${GUARDIUM_CA_PATH}"
		fi
		STAP_CONFIG_PARTICIPATE_IN_LOAD_BALANCING="${STAP_CONFIG_PARTICIPATE_IN_LOAD_BALANCING_FMT}${PARTICIPATE_IN_LOAD_BALANCING}"
		CONTAINER_CMD="$PRIVILEGED \
			$REQUIRED_CAPABILITIES \
			$EXTRA_CAPABILITIES \
			$STAP_CONFIG_TAP_TAP_IP \
			$STAP_CONFIG_TAP_PRIVATE_TAP_IP \
			$STAP_CONFIG_TAP_FORCE_SERVER_IP \
			$STAP_CONFIG_PROXY_GROUP_UUID \
			$STAP_CONFIG_PROXY_GROUP_MEMBER_COUNT \
			$STAP_CONFIG_PROXY_DB_HOST \
			$STAP_CONFIG_PROXY_NUM_WORKERS \
			$STAP_CONFIG_PROXY_PROXY_PROTOCOL \
			$STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE \
			$STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE \
			$STAP_CONFIG_DB_0_REAL_DB_PORT \
			$STAP_CONFIG_PROXY_LISTEN_PORT \
			$STAP_CONFIG_PROXY_DEBUG \
			$STAP_CONFIG_PROXY_SECRET \
			$STAP_CONFIG_PROXY_CSR_NAME \
			$STAP_CONFIG_PROXY_CSR_COUNTRY \
			$STAP_CONFIG_PROXY_CSR_PROVINCE \
			$STAP_CONFIG_PROXY_CSR_CITY \
			$STAP_CONFIG_PROXY_CSR_ORGANIZATION \
			$STAP_CONFIG_PROXY_CSR_KEYLENGTH \
			$STAP_CONFIG_DB_0_DB_TYPE \
			$STAP_CONFIG_PARTICIPATE_IN_LOAD_BALANCING \
			$STAP_CONFIG_SQLGUARD_CERT_CN \
			$STAP_CONFIG_GUARDIUM_CA_PATH \
			$STAP_CONFIG_TAP_TENANT_ID"

		return 0
	fi
	return 1
}

set_config_vars() {
	STAP_CONFIG_TAP_TAP_IP="${STAP_CONFIG_TAP_TAP_IP_FMT}${TAP_IP}"
	STAP_CONFIG_TAP_PRIVATE_TAP_IP="${STAP_CONFIG_TAP_PRIVATE_TAP_IP_FMT}${PRIVATE_TAP_IP}"
	STAP_CONFIG_TAP_FORCE_SERVER_IP="${STAP_CONFIG_TAP_FORCE_SERVER_IP_FMT}${FORCE_SERVER_IP}"

	STAP_CONFIG_PROXY_GROUP_MEMBER_COUNT="${STAP_CONFIG_PROXY_GROUP_MEMBER_COUNT_FMT}${NUMBER_OF_CONTAINERS}"
	STAP_CONFIG_PROXY_GROUP_UUID="${STAP_CONFIG_PROXY_GROUP_UUID_FMT}${UUID}"
	if [ "${DB_HOST}" != "" ]; then
		STAP_CONFIG_PROXY_DB_HOST="${STAP_CONFIG_PROXY_DB_HOST_FMT}${DB_HOST}"
	fi
	if [ "${DB_PORT}" != "" ]; then
		STAP_CONFIG_DB_0_REAL_DB_PORT="${STAP_CONFIG_DB_0_REAL_DB_PORT_FMT}${DB_PORT}"
	fi
	if [ "${DB_TYPE}" != "" ]; then
		STAP_CONFIG_DB_0_DB_TYPE="${STAP_CONFIG_DB_0_DB_TYPE_FMT}${DB_TYPE}"
	fi
	STAP_CONFIG_PROXY_LISTEN_PORT="${STAP_CONFIG_PROXY_LISTEN_PORT_FMT}${LISTEN_PORT}"
	STAP_CONFIG_PROXY_DEBUG="${STAP_CONFIG_PROXY_DEBUG_FMT}${DEBUG}"
	STAP_CONFIG_PROXY_NUM_WORKERS="${STAP_CONFIG_PROXY_NUM_WORKERS_FMT}${NUM_WORKERS}"
	STAP_CONFIG_PROXY_PROXY_PROTOCOL="${STAP_CONFIG_PROXY_PROXY_PROTOCOL_FMT}${PROXY_PROTOCOL}"
	if [ $INVALID_CERT_DISCO = "Y" ]; then
		STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE="${STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE_FMT}1"
	else
		STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE="${STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE_FMT}0"
	fi
	if [ $INVALID_CERT_NOTIFY = "Y" ]; then
		STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE="${STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE_FMT}1"
	else
		STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE="${STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE_FMT}0"
	fi

	STAP_CONFIG_PROXY_SECRET="${STAP_CONFIG_PROXY_SECRET_FMT}${TOKEN}"

	STAP_CONFIG_PROXY_CSR_NAME="${STAP_CONFIG_PROXY_CSR_NAME_FMT}${CSR_NAME}"
	STAP_CONFIG_PROXY_CSR_COUNTRY="${STAP_CONFIG_PROXY_CSR_COUNTRY_FMT}${CSR_COUNTRY}"
	STAP_CONFIG_PROXY_CSR_PROVINCE="${STAP_CONFIG_PROXY_CSR_PROVINCE_FMT}${CSR_PROVINCE}"
	STAP_CONFIG_PROXY_CSR_CITY="${STAP_CONFIG_PROXY_CSR_CITY_FMT}${CSR_CITY}"
	STAP_CONFIG_PROXY_CSR_ORGANIZATION="${STAP_CONFIG_PROXY_CSR_ORGANIZATION_FMT}${CSR_ORGANIZATION}"
	STAP_CONFIG_PROXY_CSR_KEYLENGTH="${STAP_CONFIG_PROXY_CSR_KEYLENGTH_FMT}${CSR_KEYLENGTH}"

	STAP_CONFIG_TAP_TENANT_ID=
	if [ "$TENANT_ID" != "" ]; then
		STAP_CONFIG_TAP_TENANT_ID="${STAP_CONFIG_TAP_TENANT_ID_FMT}${TENANT_ID}"
	fi

	i=0
	SQLGUARD_PARAMS=
	for C in `echo $COLLECTOR | sed 's/,/ /g'`; do
		SQLGUARD_PARAMS="${SQLGUARD_PARAMS}${STAP_CONFIG_SQLGUARD_FMT}${i}${STAP_CONFIG_SQLGUARD_IP_FMT}${C} "
		i=`expr $i + 1`
	done
	STAP_CONFIG_GUARDIUM_CA_PATH=""
	STAP_CONFIG_SQLGUARD_CERT_CN=""
	if [ "$SQLGUARD_CERT_CN" != "" ]; then
		STAP_CONFIG_GUARDIUM_CA_PATH="${STAP_CONFIG_GUARDIUM_CA_PATH_FMT}${GUARDIUM_CA_PATH}"
		STAP_CONFIG_SQLGUARD_CERT_CN="${STAP_CONFIG_SQLGUARD_CERT_CN_FMT}${SQLGUARD_CERT_CN}"
	fi
	STAP_CONFIG_PARTICIPATE_IN_LOAD_BALANCING="${STAP_CONFIG_PARTICIPATE_IN_LOAD_BALANCING_FMT}${PARTICIPATE_IN_LOAD_BALANCING}"
}

target_has_enough_memory() {
	TARGET_HOST=$1
	TARGET_USER=$2
	TARGET_MEM=$3

	MEMINFO=`ssh ${TARGET_USER}@${TARGET_HOST} cat /proc/meminfo`
	MEMFREE=`echo "${MEMINFO}" | grep "^MemFree" | awk '{ print $2 }'`
	SWAPFREE=`echo "${MEMINFO}" | grep "^SwapFree" | awk '{ print $2 }'`

	if [ "${MEMFREE}" = "" ] || [ "${SWAPFREE}" = "" ]; then
		return 1
	fi

	if [ "`echo ${MEMFREE} | sed 's/[0-9]//g'`" != "" ]; then
		return 1
	fi
	if [ "`echo ${SWAPFREE} | sed 's/[0-9]//g'`" != "" ]; then
		return 1
	fi

	MEMFREE=`expr $MEMFREE / 1024`
	SWAPFREE=`expr $SWAPFREE / 1024`
	TARGET_MEMORY_FREE=`expr $MEMFREE + $SWAPFREE`

	if [ $TARGET_MEMORY_FREE -ge $TARGET_MEM ]; then
		return 0;
	fi

	return 1
}

if [ "$ACTION" = "C" ]; then
	echo "Creating new cluster, description will be stored in $STATE_FILE"
	if [ -f $STATE_FILE ]; then
		echo "$STATE_FILE already exists.  If you wish to replace the file, please delete and run again"
		do_usage
		exit 1
	fi
	touch $STATE_FILE
	if [ ! -f $STATE_FILE ]; then
		echo "Could not create $STATE_FILE!"
		do_usage
		exit 1
	fi
	echo "PORTRANGE_STATE=$SVC_PORT_RANGE" >> $STATE_FILE

	# Warn if /proc/sys/kernel/core_pattern matches doesn't match recommendation
	# Pull in the container image to the environment
	for HOST in `echo $SVC_HOST | sed 's/,/ /g'`; do
		TARGET_CORE_PATTERN=`ssh ${SVC_HOST_USER}@${HOST} cat /proc/sys/kernel/core_pattern`
		if [ $? -ne 0 ]; then
			echo "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
			echo "Couldn't verify /proc/sys/kernel/core_pattern on $HOST"
			echo "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		else
			if [ "$TARGET_CORE_PATTERN" != "$SUGGESTED_CORE_PATTERN" ]; then
				echo "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
				echo "/proc/sys/kernel/core_pattern on $HOST is \"$TARGET_CORE_PATTERN\""
				echo "Recommended setting is \"$SUGGESTED_CORE_PATTERN\" for automatic collection of core files in diagnostics"
				echo "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
			fi
		fi
		if [ "$SVC_IMAGE" != "" ] && echo $SVC_IMAGE | grep -qv "^localhost"; then
			IMAGE_PULLED=0
			PULL_RESULT=`ssh ${SVC_HOST_USER}@${HOST} ${REMOTE_DOCKER_CMD} pull $SVC_IMAGE 2>& 1`
			PULL_RETVAL=$?
			if [ $PULL_RETVAL -ne 0 ]; then
				if [ "$REPO_USER" != "" ]; then
					ssh ${SVC_HOST_USER}@${HOST} "${REMOTE_DOCKER_CMD} login --username $REPO_USER --password $REPO_PASS"
					if [ $? -eq 0 ]; then
						ssh ${SVC_HOST_USER}@${HOST} ${REMOTE_DOCKER_CMD} pull $SVC_IMAGE
						if [ $? -eq 0 ]; then
							IMAGE_PULLED=1
						fi
					fi
				fi
			else
				echo "$PULL_RESULT"
				IMAGE_PULLED=1
			fi
			if [ $IMAGE_PULLED -ne 1 ]; then
				echo "$PULL_RESULT"
				echo "Unable to pull container image.  host: $HOST, host user: $SVC_HOST_USER, image: $SVC_IMAGE, repo user: $REPO_USER"
				do_usage
				exit 1
			fi
		fi
	done

	set_config_vars

	# ------------------------------------------------
	# Create the requested environment


	if is_developer_cluster; then
		developer_cluster_create_config
	fi

	# Start the containers
	if ! is_developer_cluster; then
		CONTAINER_CMD="$PRIVILEGED \
			$REQUIRED_CAPABILITIES \
			$EXTRA_CAPABILITIES \
			$STAP_CONFIG_TAP_TAP_IP \
			$STAP_CONFIG_TAP_PRIVATE_TAP_IP \
			$STAP_CONFIG_TAP_FORCE_SERVER_IP \
			$STAP_CONFIG_PROXY_GROUP_UUID \
			$STAP_CONFIG_PROXY_GROUP_MEMBER_COUNT \
			$STAP_CONFIG_PROXY_DB_HOST \
			$STAP_CONFIG_PROXY_NUM_WORKERS \
			$STAP_CONFIG_PROXY_PROXY_PROTOCOL \
			$STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE \
			$STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE \
			$STAP_CONFIG_DB_0_REAL_DB_PORT \
			$STAP_CONFIG_PROXY_LISTEN_PORT \
			$STAP_CONFIG_PROXY_DEBUG \
			$STAP_CONFIG_PROXY_SECRET \
			$STAP_CONFIG_PROXY_CSR_NAME \
			$STAP_CONFIG_PROXY_CSR_COUNTRY \
			$STAP_CONFIG_PROXY_CSR_PROVINCE \
			$STAP_CONFIG_PROXY_CSR_CITY \
			$STAP_CONFIG_PROXY_CSR_ORGANIZATION \
			$STAP_CONFIG_PROXY_CSR_KEYLENGTH \
			$STAP_CONFIG_DB_0_DB_TYPE \
			$STAP_CONFIG_PARTICIPATE_IN_LOAD_BALANCING \
			$STAP_CONFIG_GUARDIUM_CA_PATH \
			$STAP_CONFIG_SQLGUARD_CERT_CN \
			$STAP_CONFIG_TAP_TENANT_ID"
	else
		developer_cluster_set_command
	fi

	# Build up the host list
	i=0
	while [ $i -lt $NUMBER_OF_CONTAINERS ]; do
		SVC_HOSTS="$SVC_HOST,$SVC_HOSTS"
		i=`expr $i + 1`
	done

	INSTANCE=0
	REMOVAL_CMD=""
	SERVICE_CONTAINER_MSGS=""
	for INSTANCE_HOST in `echo $SVC_HOSTS | cut -d',' -f1-$NUMBER_OF_CONTAINERS | sed 's/,/ /g'`; do
		if ! is_developer_cluster; then
			MAX_HOSTNAME_LEN=63
			NAME="`echo gext${INSTANCE}-$UUID | cut -c -$MAX_HOSTNAME_LEN`"
			NAME_LEN=`echo $NAME | wc -c`
			PREFIX_LEN=`expr $MAX_HOSTNAME_LEN - $NAME_LEN - 1`
			if [ $PREFIX_LEN -gt 0 ]; then
				INTERNAL_HOSTNAME="`echo ${INSTANCE_HOST} | sed 's/\..*//' | cut -c -$PREFIX_LEN`-$NAME"
			else
				INTERNAL_HOSTNAME="$NAME"
			fi
			println "Creating service container $NAME on $HOST"
			# println "Internal hostname will be $INTERNAL_HOSTNAME"
			# If we have a fake collector (GSERV) then it'll run locally on some containers.  If
			# that is the case, the firewall dictates that we much use the container IP and not the
			# external IP of the system
			if [ "$GSERV_IP" != "" ] && [ "$COLLECTOR" = "$HOST" ]; then
				STAP_CONFIG_SQLGUARD_0_SQLGUARD_IP="${STAP_CONFIG_SQLGUARD_FMT}0${STAP_CONFIG_SQLGUARD_IP_FMT}${GSERV_IP}"
				SQLGUARD_PARAMS=$STAP_CONFIG_SQLGUARD_0_SQLGUARD_IP
			fi
			EXPORTED_PORT=`find_available_port_in_range $INSTANCE_HOST $SVC_HOST_USER $SVC_PORT_RANGE`
			if [ $? -eq 1 ]; then
				if target_has_enough_memory ${INSTANCE_HOST} ${SVC_HOST_USER} ${CONTAINER_RECOMMENDED_MEMORY_FREE}; then
					CONTAINER_HASH=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} run --restart unless-stopped --hostname $INTERNAL_HOSTNAME --name $NAME -d $CONTAINER_CMD $SQLGUARD_PARAMS $ENVVARS $MOUNTS -p=${SVC_HOST_EXPORT_ANY_IP}${EXPORTED_PORT}:${LISTEN_PORT}/tcp $SVC_IMAGE`
					CONTAINER_OK=$?
				else
					echo "Error: Insufficient memory on target host ${INSTANCE_HOST}.  Free: ${TARGET_MEMORY_FREE} Recommended: ${CONTAINER_RECOMMENDED_MEMORY_FREE}"
					CONTAINER_OK=1
				fi
			else
				echo "Error: Unable to find free port in range ${SVC_PORT_RANGE} on host ${INSTANCE_HOST}"
				CONTAINER_OK=1
			fi
		else
			developer_cluster_make_container
			CONTAINER_OK=$?
		fi
		INSTANCE=`expr $INSTANCE + 1`
		if [ $CONTAINER_OK -eq 0 ]; then
			HASHES="$HASHES $CONTAINER_HASH"
			CONTAINER_IP=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} inspect $CONTAINER_HASH | grep "\"IPAddress\"" | sed -n '1p' | awk '{ print $2 }' | cut -d ',' -f1 | sed "s/\"//g"`
			HOST_PORT=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} port $CONTAINER_HASH | cut -d':' -f2`
			SERVICE_CONTAINER_MSGS="${SERVICE_CONTAINER_MSGS}Started service container : $CONTAINER_HASH (CONTAINER_IP $CONTAINER_IP, HOST ${INSTANCE_HOST}, EXTERNAL PORT $HOST_PORT)\n"
			# TAG: CONTAINER STATE FORMAT
			echo "${INSTANCE_HOST},${HOST_PORT},${LISTEN_PORT},${DB_PORT},${NAME}" >> $STATE_FILE
			if [ "$REMOVAL_CMD" = "" ]; then
				REMOVAL_CMD="ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} rm -f $CONTAINER_HASH"
			else
				REMOVAL_CMD="ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} rm -f $CONTAINER_HASH ; $REMOVAL_CMD"
			fi
			if is_developer_cluster || is_developer_automated_changes; then
				TMPDIR=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} mktemp -d`
				ssh ${SVC_HOST_USER}@${INSTANCE_HOST} rm -rf $TMPDIR/gext_setup
				ssh ${SVC_HOST_USER}@${INSTANCE_HOST} mkdir $TMPDIR/gext_setup
				if is_developer_cluster; then
					developer_do_cluster_postconfig
				fi
				if is_developer_automated_changes; then
					developer_do_automated_postconfig
				fi
				ssh ${SVC_HOST_USER}@${INSTANCE_HOST} rm -rf $TMPDIR
			fi
		else
			echo "Error: Couldn't create Guardium External S-TAP container"
		fi
	done

	# Cleanup
	developer_create_cleanup

	lb_import_state $STATE_FILE
	lb_apply_config
	lb_cleanup

	echo
	# print out our messages
	println "================================================="
	developer_additional_containers_msgs
	println "$SERVICE_CONTAINER_MSGS"
	println "================================================="
elif [ "$ACTION" = "P" ]; then
	echo "Printing service container env vars, description will be stored in $STATE_FILE"
	if [ -f $STATE_FILE ]; then
		echo "$STATE_FILE already exists.  If you wish to replace the file, please delete and run again"
		do_usage
		exit 1
	fi
	touch $STATE_FILE
	if [ ! -f $STATE_FILE ]; then
		echo "Could not create $STATE_FILE!"
		do_usage
		exit 1
	fi


	set_config_vars

	if is_developer_cluster; then
		developer_cluster_create_config
	fi

	NAME="gext${INSTANCE}-$UUID"
	# Start the containers
	if ! is_developer_cluster; then
		CONTAINER_CMD="$PRIVILEGED \
			$REQUIRED_CAPABILITIES \
			$EXTRA_CAPABILITIES \
			$STAP_CONFIG_TAP_TAP_IP \
			$STAP_CONFIG_TAP_PRIVATE_TAP_IP \
			$STAP_CONFIG_TAP_FORCE_SERVER_IP \
			$STAP_CONFIG_PROXY_GROUP_UUID \
			$STAP_CONFIG_PROXY_GROUP_MEMBER_COUNT \
			$STAP_CONFIG_PROXY_DB_HOST \
			$STAP_CONFIG_PROXY_NUM_WORKERS \
			$STAP_CONFIG_PROXY_PROXY_PROTOCOL \
			$STAP_CONFIG_PROXY_DISCONNECT_ON_INVALID_CERTIFICATE \
			$STAP_CONFIG_PROXY_NOTIFY_ON_INVALID_CERTIFICATE \
			$STAP_CONFIG_DB_0_REAL_DB_PORT \
			$STAP_CONFIG_PROXY_LISTEN_PORT \
			$STAP_CONFIG_PROXY_DEBUG \
			$STAP_CONFIG_PROXY_SECRET \
			$STAP_CONFIG_PROXY_CSR_NAME \
			$STAP_CONFIG_PROXY_CSR_COUNTRY \
			$STAP_CONFIG_PROXY_CSR_PROVINCE \
			$STAP_CONFIG_PROXY_CSR_CITY \
			$STAP_CONFIG_PROXY_CSR_ORGANIZATION \
			$STAP_CONFIG_PROXY_CSR_KEYLENGTH \
			$STAP_CONFIG_DB_0_DB_TYPE \
			$SQLGUARD_PARAMS \
			$STAP_CONFIG_PARTICIPATE_IN_LOAD_BALANCING \
			$STAP_CONFIG_GUARDIUM_CA_PATH \
			$STAP_CONFIG_SQLGUARD_CERT_CN \
			$STAP_CONFIG_TAP_TENANT_ID"
	else
		developer_cluster_set_command
	fi

	CONTAINER_CMD=`echo "$CONTAINER_CMD" | sed 's/\t/\n/g' | sed -n '/-/p'`
	SERVICE_CONTAINER_MSGS="$SERVICE_CONTAINER_MSGS \n\
Containers would be started with... \n\
$CONTAINER_CMD"
	echo "$CONTAINER_CMD" > $STATE_FILE

	# print out our messages
	println "================================================="
	developer_additional_containers_msgs
	println "$SERVICE_CONTAINER_MSGS"
	println "================================================="
elif [ "$ACTION" = "D" ]; then
	echo "Removing cluster described by $STATE_FILE"
	if [ ! -f $STATE_FILE ]; then
		echo "$STATE_FILE does not exist!"
		do_usage
		exit 1
	fi
	WARNINGS=
	ZOMBIES=
	for LINE in `cat $STATE_FILE`; do
		# TAG: CONTAINER STATE FORMAT
		# $HOST,$HOST_PORT,$LISTEN_PORT,$DB_PORT,$NAME
		NOT_GEXT_INSTANCE=0
		if echo $LINE | grep "PORTRANGE_STATE=" 2>&1 > /dev/null; then
			# Skip this line
			continue
		elif ! is_developer_container; then
			INSTANCE_HOST=`echo $LINE | cut -d',' -f1`
			NAME=`echo $LINE | cut -d',' -f5`
		else
			NOT_GEXT_INSTANCE=1
		fi
		HASH=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} "${REMOTE_DOCKER_CMD} ps -qf name=$NAME" < /dev/null`
		if [ "$HASH" != "" ]; then
			echo "Removing container $HASH ($NAME) from host ${INSTANCE_HOST}"
			if [ $NOT_GEXT_INSTANCE -eq 0 ]; then
				ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} rename $NAME ${NAME}-stopping-$$
				ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} exec ${NAME}-stopping-$$ gpctl shutdown
				graceful_terminate ${INSTANCE_HOST} $NAME "-stopping-$$"
			else
				ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} rm -f $NAME
			fi
		else
			echo "Unable to check for container ${NAME} on ${INSTANCE_HOST}"
			do_usage
			exit 1
		fi
	done

	lb_import_state $STATE_FILE
	lb_teardown_config
	lb_cleanup
	rm -f $STATE_FILE

	add_zombies_to_file $STATE_FILE

	println "================================================="
	println "$WARNINGS"
	println "================================================="
elif [ "$ACTION" = "Z" ]; then
	echo "Removing zombies described by $STATE_FILE"
	if [ ! -f $STATE_FILE ]; then
		echo "$STATE_FILE does not exist!"
		do_usage
		exit 1
	fi
	WARNINGS=
	ZOMBIES=
	NEW_STATE=
	for LINE in `cat $STATE_FILE`; do
		# TAG: CONTAINER STATE FORMAT
		# $HOST,$HOST_PORT,$LISTEN_PORT,$DB_PORT,$NAME
		NOT_ZOMBIE_INSTANCE=0
		if echo $LINE | grep -q "^ZOMBIE_STATE="; then
			LINE=`echo $LINE | sed 's/ZOMBIE_STATE=//'`
			INSTANCE_HOST=`echo $LINE | cut -d',' -f1`
			NAME=`echo $LINE | cut -d',' -f2`
		else
			NEW_STATE="$NEW_STATE $LINE"
			NOT_ZOMBIE_INSTANCE=1
		fi
		if [ $NOT_ZOMBIE_INSTANCE -eq 0 ]; then
			HASH=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} "${REMOTE_DOCKER_CMD} ps -qf name=$NAME" < /dev/null`
			if [ "$HASH" != "" ]; then
				echo "Removing container $HASH ($NAME) from host $INSTANCE_HOST"
				SHUTTING_DOWN=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} exec ${NAME} ls /etc/gp/.gp.SHUTTING_DOWN 2> /dev/null`
				SHUT_DOWN=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} exec ${NAME} ls /etc/gp/.gp.SHUTDOWN 2> /dev/null`
				if [ "${SHUTTING_DOWN}" = "" ] && [ "${SHUT_DOWN}" = "" ]; then
					# Don't call it twice
					ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} exec ${NAME} gpctl shutdown
				fi
				graceful_terminate $INSTANCE_HOST $NAME ""
			else
				echo "Unable to check for containers on ${INSTANCE_HOST}"
				do_usage
				exit 1
			fi
		fi
	done

	STATE_EXISTS=0
	:> $STATE_FILE
	for LINE in $NEW_STATE; do
		if [ "$LINE" != "" ]; then
			echo $LINE >> $STATE_FILE
			STATE_EXISTS=1
		fi
	done
	if [ $STATE_EXISTS -eq 0 ]; then
		rm -f $STATE_FILE
	fi

	add_zombies_to_file $STATE_FILE

	println "================================================="
	println "$WARNINGS"
	println "================================================="
elif [ "$ACTION" = "U" ]; then
	echo "Upgrading cluster described by $STATE_FILE"
	if [ ! -f $STATE_FILE ]; then
		echo "$STATE_FILE does not exist!"
		do_usage
		exit 1
	fi
	SVC_PORT_RANGE=`cat $STATE_FILE | sed -n 's/PORTRANGE_STATE=//p'`
	STATE_FILE_POST_UPGRADE="$STATE_FILE-post-upgrade"
	if [ -f $STATE_FILE_POST_UPGRADE ]; then
		echo "$STATE_FILE_POST_UPGRADE already exists.  If you wish to replace the file, please delete and run again"
		do_usage
		exit 1
	fi
	touch $STATE_FILE_POST_UPGRADE
	if [ ! -f $STATE_FILE_POST_UPGRADE ]; then
		echo "Could not create $STATE_FILE_POST_UPGRADE!"
		do_usage
		exit 1
	fi

	CONTAINER_CMD=""
	while read STATE_LINE; do
		if echo $STATE_LINE | grep -q "STATE="; then
			continue
		fi
		INSTANCE_NAME="`echo $STATE_LINE | cut -d',' -f5`"
		INSTANCE_HOST="`echo $STATE_LINE | cut -d',' -f1`"
		if [ "$INSTANCE_HOST" = "" ] || [ "$INSTANCE_NAME" = "" ]; then
			echo "Unable to process state file for upgrade"
			exit 1
		fi

		CA_FILE=
		get_config_from_container $INSTANCE_HOST $INSTANCE_NAME
		if [ $? -eq 0 ]; then
			break
		fi
	done < $STATE_FILE

	if [ "$CONTAINER_CMD" = "" ]; then
		echo "Unable to determine Guardium External S-TAP configuration from $INSTANCE_NAME on $INSTANCE_HOST"
		upgrade_abort
		exit 1
	fi

	lb_import_state $STATE_FILE
	SERVICE_CONTAINER_MSGS=""
	UPGRADING=
	WARNINGS=
	ZOMBIES=
	for STATE_LINE in `cat $STATE_FILE`; do
		if echo $STATE_LINE | grep -q "STATE="; then
			if echo $STATE_LINE | grep -q "ZOMBIE_STATE="; then
				ZOMBIES="${ZOMBIES} ${STATE_LINE}"
			else
				echo "$STATE_LINE" >> $STATE_FILE_POST_UPGRADE
			fi
			continue
		fi
		INSTANCE_NAME="`echo $STATE_LINE | cut -d',' -f5`"
		INSTANCE_HOST="`echo $STATE_LINE | cut -d',' -f1`"
		INSTANCE_PORT="`echo $STATE_LINE | cut -d',' -f2`"
		if [ "$INSTANCE_HOST" = "" ] || [ "$INSTANCE_NAME" = "" ]; then
			echo "Unable to process state file for upgrade"
			exit 1
		fi
		INTERNAL_HOSTNAME="`echo ${INSTANCE_HOST} | sed 's/\..*//' `-$INSTANCE_NAME"

		println "Replacing service container $INSTANCE_NAME on $INSTANCE_HOST"

		#ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} pull $SVC_IMAGE
		#if [ $? -ne 0 ]; then
		#	echo "Unable to pull $SVC_IMAGE on $INSTANCE_HOST"
		#	upgrade_abort
		#	exit 1
		#fi

		if [ "$SVC_IMAGE" != "" ] && echo $SVC_IMAGE | grep -qv "^localhost"; then
			IMAGE_PULLED=0
			PULL_RESULT=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} pull $SVC_IMAGE 2>& 1`
			PULL_RETVAL=$?
			if [ $PULL_RETVAL -ne 0 ]; then
				if [ "$REPO_USER" != "" ]; then
					ssh ${SVC_HOST_USER}@${INSTANCE_HOST} "${REMOTE_DOCKER_CMD} login --username $REPO_USER --password $REPO_PASS"
					if [ $? -eq 0 ]; then
						ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} pull $SVC_IMAGE
						if [ $? -eq 0 ]; then
							IMAGE_PULLED=1
						fi
					fi
				fi
			else
				echo "$PULL_RESULT"
				IMAGE_PULLED=1
			fi
			if [ $IMAGE_PULLED -ne 1 ]; then
				echo "$PULL_RESULT"
				echo "Unable to pull container image.  host: $INSTANCE_HOST, host user: $SVC_HOST_USER, image: $SVC_IMAGE, repo user: $REPO_USER"
				upgrade_abort
				exit 1
			fi
		fi

		UPGRADING="$UPGRADING $INSTANCE_NAME,$INSTANCE_HOST"
		# Rename original container
		ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} rename $INSTANCE_NAME ${INSTANCE_NAME}-upgrading-$$
		if [ $? -ne 0 ]; then
			echo "Unable to rename $INSTANCE_NAME on $INSTANCE_HOST for upgrade"
			upgrade_abort
			exit 1
		fi

		# Find a free port in the range for the new container
		EXPORTED_PORT=`find_available_port_in_range $INSTANCE_HOST $SVC_HOST_USER $SVC_PORT_RANGE`
		if [ $? -eq 1 ]; then
			# Start replacement container
			CONTAINER_HASH=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} run --restart unless-stopped --hostname $INTERNAL_HOSTNAME --name $INSTANCE_NAME -d $CONTAINER_CMD $SQLGUARD_PARAMS $ENVVARS $MOUNTS -p=${SVC_HOST_EXPORT_ANY_IP}${EXPORTED_PORT}:${LISTEN_PORT}/tcp $SVC_IMAGE`
			CONTAINER_OK=$?
			if [ $CONTAINER_OK -eq 0 ]; then
				ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} exec ${INSTANCE_NAME}-upgrading-$$ gpctl shutdown
				if [ $? -ne 0 ]; then
					echo "Unable to set container ${INSTANCE_NAME}-upgrading-$$ to shutdown state"
					ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} rename ${INSTANCE_NAME}-upgrading-$$ ${INSTANCE_NAME}-zombie-$$
					ZOMBIES="${ZOMBIES} ZOMBIE_STATE=${INSTANCE_HOST},${INSTANCE_NAME}-zombie-$$"
					WARNINGS="$WARNINGS\n\
Old container ${INSTANCE_NAME}-zombie-$$ still running on host $DHOST\n\
Please close open connections using this container and remove when desired.\n\
When the file /etc/gp/.gp.SHUTDOWN exists in the container, there are no\n\
open connections that would be terminated by removal.\n\
\n"
					lb_remove_one $INSTANCE_HOST $INSTANCE_PORT
					upgrade_abort
					exit 1
				fi

				lb_remove_one $INSTANCE_HOST $INSTANCE_PORT

				HASHES="$HASHES $CONTAINER_HASH"
				CONTAINER_IP=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} inspect $CONTAINER_HASH | grep "\"IPAddress\"" | sed -n '1p' | awk '{ print $2 }' | cut -d ',' -f1 | sed "s/\"//g"`
				HOST_PORT=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} ${REMOTE_DOCKER_CMD} port $CONTAINER_HASH | cut -d':' -f2`
				SERVICE_CONTAINER_MSGS="${SERVICE_CONTAINER_MSGS}Started service container : $CONTAINER_HASH (CONTAINER_IP $CONTAINER_IP, HOST $INSTANCE_HOST, EXTERNAL PORT $HOST_PORT)\n"
				# TAG: CONTAINER STATE FORMAT
				echo "$INSTANCE_HOST,$HOST_PORT,$LISTEN_PORT,$DB_PORT,$INSTANCE_NAME" >> $STATE_FILE_POST_UPGRADE
				if is_developer_automated_changes;then 
					TMPDIR=`ssh ${SVC_HOST_USER}@${INSTANCE_HOST} mktemp -d`
					ssh ${SVC_HOST_USER}@${INSTANCE_HOST} rm -rf $TMPDIR/gext_setup
					ssh ${SVC_HOST_USER}@${INSTANCE_HOST} mkdir $TMPDIR/gext_setup

					developer_do_automated_postconfig

					ssh ${SVC_HOST_USER}@${INSTANCE_HOST} rm -rf $TMPDIR
				fi

				lb_add_one $INSTANCE_HOST $HOST_PORT

				lb_apply_config
			else
				echo "Error: Couldn't create Guardium External S-TAP container"
				upgrade_abort
				exit 1
			fi
		else
			echo "Error: Unable to find free port in range ${SVC_PORT_RANGE} on host ${INSTANCE_HOST}"
			upgrade_abort
			exit 1
		fi
	done


	WARNINGS=""
	for STATE_LINE in `cat $STATE_FILE`; do
		if echo $STATE_LINE | grep -q "STATE="; then
			continue
		fi
		INSTANCE_NAME="`echo $STATE_LINE | cut -d',' -f5`"
		INSTANCE_HOST="`echo $STATE_LINE | cut -d',' -f1`"
		
		graceful_terminate $INSTANCE_HOST ${INSTANCE_NAME} "-upgrading-$$"
	done

	rm -f $STATE_FILE
	mv $STATE_FILE_POST_UPGRADE $STATE_FILE

	add_zombies_to_file $STATE_FILE

	echo
	# print out our messages
	println "================================================="
	println "$SERVICE_CONTAINER_MSGS"
	println "$WARNINGS"
	println "================================================="
elif [ "$ACTION" = "R" ]; then
	echo "Removing interception from cluster described by $STATE_FILE"
	if [ ! -f $STATE_FILE ]; then
		echo "$STATE_FILE does not exist!"
		do_usage
		exit 1
	fi
	WARNINGS=

	CONTAINER_CMD=""
	while read STATE_LINE; do
		if echo $STATE_LINE | grep -q "STATE="; then
			continue
		fi
		INSTANCE_NAME="`echo $STATE_LINE | cut -d',' -f5`"
		INSTANCE_HOST="`echo $STATE_LINE | cut -d',' -f1`"
		if [ "$INSTANCE_HOST" = "" ] || [ "$INSTANCE_NAME" = "" ]; then
			echo "Unable to process state file for removing interception"
			exit 1
		fi

		CA_FILE=
		get_config_from_container $INSTANCE_HOST $INSTANCE_NAME
		if [ $? -eq 0 ]; then
			break
		fi
	done < $STATE_FILE

	lb_import_state $STATE_FILE
	lb_redirect_around_containers $DB_HOST $DB_PORT
	lb_apply_config
	lb_cleanup

	println "================================================="
	println "$WARNINGS"
	println "================================================="
elif [ "$ACTION" = "E" ]; then
	echo "Enabling interception with cluster described by $STATE_FILE"
	if [ ! -f $STATE_FILE ]; then
		echo "$STATE_FILE does not exist!"
		do_usage
		exit 1
	fi
	WARNINGS=

	lb_import_state $STATE_FILE
	lb_apply_config
	lb_cleanup

	println "================================================="
	println "$WARNINGS"
	println "================================================="
fi
