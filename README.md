## Guardium_External_S-TAP
The purpose of this project is to provide a management script that can be used to simplify deploying and managing an External S-TAP deployment.

## About the Guardium External S-TAP deployment script (container_mgmt.sh)
Since Guardium External S-TAP needs some information about your environment and you may wish to create multiple instances, a script is provided to ease deployment in your environment.  The deployment script can be called interactively or non-interactively.  While using the script interactively, parameters passed on the command-line will be used to pre-populate responses and each response entered will print out the parameter to specify the response on the command-line.  By running the script interactively, a wrapper script can be created which will reflect the configuration of the deployment and make working with it easier.

## Parameters for container_mgmt.sh
	[--lb-script <file>]                    - script to use to pull in functions for integrating with a load balancer
	                                          if not provided, load balancer will need to be configured separately

	[--svc-host <host/ip>]                  - host(s) on which to create service container(s) (comma delimited)
	                                          optional, default is "localhost"
	[--svc-host-user <username>]            - username to use for creating service container(s) on host(s)
	                                          optional, default is the current user "rojerrel"
	[--svc-port-range <X-Y>]                - exported port for the service container will be between X and Y (inclusive)
	                                          optional, default ("0") is to use the values at /proc/sys/net/ipv4/ip_local_port_range
	                                          example "32768-61000"
	[--svc-image <image>]                   - hash/name of guardium external s-tap image
	                                          required, example "icr.io/guardium-insights/guardium_external_s-tap:v11.5"
	[--repo-user <username>]                - username to log in to the repository from which the service image is pulled
	                                          optional, example "foo"
	[--repo-pass <password>]                - password for username when loging in to the repository
	                                          optional, example "bar"
	[--svc-container-num <num>]             - number of service containers to create
	                                          optional, default is "1"

	[--ni]                                  - run this script non-interactively
	[--c]                                   - create a cluster
	[--p]                                   - do not create a cluster, just print service container env vars (output saved in state file)
	[--r]                                   - remove interception (requires load-balancer integration script)
	[--e]                                   - enable interception (requires load-balancer integration script)
	[--u]                                   - upgrade an existing cluster
	[--d]                                   - delete an existing cluster
	[--z]                                   - clean up zombie instances

	[--uuid <UUID>]                         - specify <UUID> for the guardium external s-tap cluster
	                                          optional, default is a random UUID like "2365516c-38e8-48e9-9827-70f2bfc7b09f"
	[--proxy-secret <string>]               - use <string> as shared secret to retrieve key from collector for guardium external s-tap
	                                          required if traffic is encrypted, optional if not, comes from CLI on collector
	[--sqlguard-ip <host/ip>]               - specify collector list <host/ip> (comma delimited) for guardium external s-tap to relay decrypted traffic (primary is first)
	                                          required, example "10.0.0.2"
	[--participate-in-load-balancing <num>] - STAP load balancing parameter
	                                          optional, default is 0 -  0: failover/no lb, 1: split, 2: redundancy, 3: not allowed, 4: threaded
	[--sqlguard-cert-cn <cn>]               - CN to match when verifying collector certificates
	                                          requires a derived container image with a CA populated at /etc/guardium/guardium_ca.crt
	[--db-host <host/ip>]                   - database <host/ip> to which cluster sends traffic
	                                          optional, can be set from collector after creation.  example "10.0.0.3"
	[--db-port <port>]                      - database <port> to which cluster sends traffic
	                                          optional, can be set from collector after creation.  example "1526"
	[--db-type <string>]                    - specify DB type for traffic that is being proxied
	                                          optional, can be set from collector after creation.
	                                          must be one of "oracle", "mssql", "sybase", "mongodb", "db2", "mysql", "memsql", "mariadb", "pgsql", "greenplumdb", or "verticadb"
	[--proxy-num-workers <#>]               - number of worker threads for the guardium external s-tap to use
	                                          optional, can be set from collector after creation.  example "5"
	[--proxy-protocol <#>]                  - proxy protocol is enabled for the DB traffic (0: no, 1: protocol version 1)
	                                          optional, can be set from collector after creation.  default is "0"
	[--invalid-cert-disconnect]             - disconnect if DB server certificate cannot be verified
	                                          optional, can be set from collector after creation.
	[--invalid-cert-notify]                 - log a warning if DB server certificate cannot be verified
	                                          optional, can be set from collector after creation.

	[--kill-after <#>]                      - when stopping a container, if container cannot shutdown within # seconds, forcefully remove it
	                                          optional, example "30", when not specified, script will wait 30s but container will not be
	                                          forefully removed if graceful termination does not occur.

	[--state-file <filename>]               - name of the file in which the state is recorded
	                                          required, example "./cluster_state"


## Using a Load Balancer with IBM Security Guardium External S-TAP
A load balancer is required for use with Guardium External S-TAP instances.  The load balancer provides redundancy in order to eliminate a single point of failure and in coordination with the load balancer integration script permits the Guardium External S-TAP instances to be upgraded without impacting traffic between the server and clients

Example scripts are provided to show how to integrate the deployment script with a containerized NGINX configuration
1.  lb_integration_nginx.sh 
	1. An example implementation that will spawn an NGINX container and configure it for use with the Guardium External S-TAP
1.  lb_integration_echo.sh 
	1. A blank template that simply echos to stdout the actions that should be performed

**lb_redirect_around_containers()**
Receives two parameters that describe the HOST and PORT of the server to direct traffic to instead of through the service containers.  Will change the configuration created by lb_import_state().  Used to temporarily remove interception by Guardium External S-TAP instances for debugging and testing.

**lb_add_one()**
Receives two parameters that describe the HOST and PORT of the Guardium External S-TAP service container to be added.  Using the configuration prepared in lb_import_state(), add this item to the configuration, but do not apply the configuration yet.

**lb_remove_one()**
Receives two parameters that describe the HOST and PORT of the Guardium External S-TAP service container to be removed.  Using the configuration prepared in lb_import_state(), remove this item from the configuration, but do not apply the configuration yet.

**lb_apply_config()**
Receives no parameters.  Apply the current state of the configuration to the load balancer.  May be called multiple times per run of container_mgmt.sh.

**lb_teardown_config()**
Receives no parameters.  Deactivate the load-balancer.  This function is called when the Guardium External S-TAP service containers are removed as part of an uninstallation.

**lb_cleanup()**
Receives no parameters.  Performs any cleanup necessary to remove temporary files.  Will be called only once when load balancer integration will not be called again.


## Deployment Information Checklist
1.  Docker Store login credentials
    DOCKER_STORE_USER and DOCKER_STORE_PASS
1.  Docker Store path for the Guardium External S-TAP image
    icr.io/guardium-insights/guardium_external_s-tap:v11.5
1.  Hostname(s) of the system(s) that will be running the Guardium External S-TAP instances.  List is comma-delimited.
    SERVICE_HOST_LIST
1.  Username of user that will spawn the Guardium External S-TAP instances
    SERVICE_HOST_USER
	1.  requires membership in the docker group on the host system
	1.  pubkey authentication should be configured as the deployment script will log in to the host systems multiple times via ssh
1.  Database server information
	1.  hostname or IP
            DB_SERVER_HOST
	1.  port
            DB_SERVER_PORT
	1.  database type
            DB_SERVER_TYPE
	1.  Secret token for retrieving the tuple of (Guardium External S-TAP certificate, Guardium External S-TAP private key, DB server root CA) from the Guardium Collector Appliance
            SECRET_TOKEN
1.  A load balancer integration script to manage the load balancer configuration
    LB_SCRIPT
	1.  Load-balancer is required for use with Guardium External S-TAP, but is not supplied by IBM
	1.  An example integration script is provided, along with documentation, for you to manage the load-balancer implementation that is right for you
1.  You will also need to know how many service containers you would like to create
    SERVICE_CONTAINER_COUNT


## Guardium External S-TAP Cluster Creation
Once you have collected all the necessary information for specifying how the deployment should look, including preparing the Guardium Collector for transferring a trusted certificate to the Guardium External S-TAP instances, execute the deployment script with the appropriate parameters.

	container_mgmt.sh \
		--ni \
		--c \
		--svc-image          icr.io/guardium-insights/guardium_external_s-tap:v11.5 \
		--repo-user          DOCKER_STORE_USER \
		--repo-pass          DOCKER_STORE_PASS \
		--svc-host           SERVICE_HOST_LIST \
		--svc-host-user      SERVICE_HOST_USER \
		--svc-container-num  SERVICE_CONTAINER_COUNT \
		--db-host            DB_SERVER_HOST \
		--db-type            DB_SERVER_TYPE \
		--db-port            DB_SERVER_PORT \
		--proxy-secret       SECRET_TOKEN \
		--lb-script          LB_SCRIPT \
		--state-file         cluster.state

Once the containers have been created, the state file should be kept for future use when managing the cluster

## Guardium External S-TAP Cluster Upgrade
In order to upgrade the cluster, use the deployment script and the previously created state file to specify the new container image to use.  Sessions that are currently active on the existing Guardium External S-TAP service containers will not be impacted.  The existing containers will be scheduled for deactivation and will not accept any new connections.  If the active sessions on a container are not terminated within a 30s timeout, the container will be renamed with a 'zombie' prefix and left running for later, manual, cleanup.

	container_mgmt.sh \
		--ni \
		--u \
		--svc-image     icr.io/guardium-insights/guardium_external_s-tap:v11.5 \
		--svc-host-user SERVICE_HOST_USER \
		--repo-user     DOCKER_STORE_USER \
		--repo-pass     DOCKER_STORE_PASS \
		--lb-script     LB_SCRIPT \
		--state-file    cluster.state

## Guardium External S-TAP Cluster Removal
Removal of a cluster will also gracefully shut down the existing Guardium External S-TAP service containers to prevent terminating live client connections, leaving the containers renamed with a 'zombie' suffix if the containers still have active connections after a 30s timeout.

	container_mgmt.sh \
		--ni \
		--d \
		--svc-host-user SERVICE_HOST_USER \
		--lb-script     LB_SCRIPT \
		--state-file    cluster.state

## Guardium External S-TAP Zombie Cleanup
Removal of the cluster or upgrade of the service instances can create zombie containers.  Zombie containers are service containers that continue to run because they were not able to be gracefully terminated withing a reasonable timeframe.  They don’t accept new connections, but will continue to process the connections already routing through them.  If you have zombie containers, you can periodically attempt to clean them up to release the resources that they consume.

	container_mgmt.sh \
		--ni \
		--z \
		--svc-host-user SERVICE_HOST_USER \
		--lb-script     LB_SCRIPT \
		--state-file    cluster.state

## Guardium External S-TAP Service Instance Parameter Output 
When deploying Guardium External S-TAP in the cloud, you cannot use the deployment script since each cloud service provider has a different interface for creating services.  Guardium External S-TAP instances need to have environment variables set that represent the starting configuration.  To make it simpler to determine what those parameters should be, you can call container_mgmt.sh and specify that you only want to see what parameters are needed for the containers.  This can be done non-interactively exactly the same as when specifying ‘--c’, but instead specifying ‘--p’, or interactively by choosing command ‘p’ when prompted.  Please note that the load-balancer integration script is not involved in this case and the state file will be used to record the output so that it could be processed separately by a user-provided script to deploy in cloud environments.

## Guardium External S-TAP Remove Cluster Interception
For debugging and testing purposes, it can be useful to temporarily remove the cluster from the path from client to server.  This is accomplished by adjusting the load balancer configuration to point directly to the DB server, so a load balancer integration script is required.

	container_mgmt.sh \
		--ni \
		--r \
		--lb-script    LB_SCRIPT \
		--state-file   cluster.state

## Guardium External S-TAP Enable Cluster Interception
If interception has been disabled previously using the load balancer integration, the load balancer configuration can be replaced again to reinsert the Guardium External S-TAP service instances into the network path between client and server to re-enable interception.

	container_mgmt.sh \
		--ni \
		--e \
		--lb-script    LB_SCRIPT \
		--state-file   cluster.state
