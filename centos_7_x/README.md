# Build Bare Metal Kubernetes on CentOS 7.x

## Table of contents
- [Build Bare Metal Kubernetes on CentOS 7.x](#Build-Bare-Metal-Kubernetes-on-CentOS-7.x)
  - [Table of contents](#Table-of-contents)
  - [Requirement](#Requirement)
  - [Add hosts on local and server](#Add-hosts-on-local-and-server)
  - [Install haproxy on all haproxy server](#Install-haproxy-on-all-haproxy-server)
  - [Configure haproxy on all haproxy server](#Configure-haproxy-on-all-haproxy-server)
  - [Install keepalived and conntrack on all haproxy server](#Install-keepalived-and-conntrack-on-all-haproxy-server)
  - [Configure keepalived and conntrack](#Configure-Keepalived-and-Conntrack)
    - [export environment on all haproxy server](#export-environment-on-all-haproxy-server)
    - [required directory on all haproxy server](#required-directory-on-all-haproxy-server)
    - [required script on all haproxy server](#required-script-on-all-haproxy-server)
    - [required script and config on sample-haproxy-001](#required-script-and-config-on-sample-haproxy-001)
    - [required script and config on sample-haproxy-002](#required-script-and-config-on-sample-haproxy-002)

## Requirement
- CentOS 7.x * 8
    - haproxy * 2
    - kubernetes master * 3
    - kubernetes worker * 3

## Add hosts on local and server
``` shell
export _HAPROXY_1="10.10.10.11 sample-haproxy-001"
export _HAPROXY_2="10.10.10.12 sample-haproxy-002"
export _KUBE_MASTER_1="10.10.10.13 sample-kube-master-001"
export _KUBE_MASTER_2="10.10.10.14 sample-kube-master-002"
export _KUBE_MASTER_3="10.10.10.15 sample-kube-master-003"
export _KUBE_WORKER_1="10.10.10.16 sample-kube-worker-001"
export _KUBE_WORKER_2="10.10.10.17 sample-kube-worker-002"
export _KUBE_WORKER_3="10.10.10.18 sample-kube-worker-003"

cat >> /etc/hosts << EOF
${_HAPROXY_1}
${_HAPROXY_2}
${_KUBE_MASTER_1}
${_KUBE_MASTER_2}
${_KUBE_MASTER_3}
${_KUBE_WORKER_1}
${_KUBE_WORKER_2}
${_KUBE_WORKER_3}
EOF
```

## Install Haproxy on all haproxy server
``` shell
export _HAPROXY_RPM="https://github.com/fancyshenmue/rpms.git"
export _TEMP_WORK_DIRECTORY="/tmp"
export _RPM_PATH=${_TEMP_WORK_DIRECTORY}/rpms/centos_7_x/haproxy-2.1.2-1.el7.x86_64.rpm

cd ${_TEMP_WORK_DIRECTORY}
git clone ${_HAPROXY_RPM}
rpm -hiv ${_RPM_PATH}
rm -fr ${_TEMP_WORK_DIRECTORY}/rpms
```

## Configure Haproxy on all haproxy server
``` shell
export _KUBE_MASTER_1_IP="10.10.10.13"
export _KUBE_MASTER_2_IP="10.10.10.14"
export _KUBE_MASTER_3_IP="10.10.10.15"
export _KUBE_WORKER_1_IP="10.10.10.16"
export _KUBE_WORKER_2_IP="10.10.10.17"
export _KUBE_WORKER_3_IP="10.10.10.18"
export _KUBE_MASTER_VIP="10.10.10.19"
export _KUBE_WORKER_VIP="10.10.10.20"

export _KUBE_MASTER_1_NODE="master01"
export _KUBE_MASTER_2_NODE="master02"
export _KUBE_MASTER_3_NODE="master03"
export _KUBE_WORKER_1_NODE="worker01"
export _KUBE_WORKER_2_NODE="worker02"
export _KUBE_WORKER_3_NODE="worker03"

export _HAPROXY_FRONTEND_MASTER="kubernetes-master-frontend"
export _HAPROXY_BACKEND_MASTER="kubernetes-master-backend"
export _HAPROXY_FRONTEND_MASTER_PORT="6443"
export _HAPROXY_BACKEND_MASTER_PORT="6443"

export _HAPROXY_FRONTEND_HTTP_WORKDER="kubernetes-ingress-http-frontend"
export _HAPROXY_BACKEND_HTTP_WORKDER="kubernetes-ingress-http-backend"
export _HAPROXY_FRONTEND_HTTP_WORKDER_PORT="80"
export _HAPROXY_BACKEND_HTTP_WORKDER_PORT="80"

export _HAPROXY_FRONTEND_HTTPS_WORKDER="kubernetes-ingress-https-frontend"
export _HAPROXY_BACKEND_HTTPS_WORKDER="kubernetes-ingress-https-backend"
export _HAPROXY_FRONTEND_HTTPS_WORKDER_PORT="443"
export _HAPROXY_BACKEND_HTTPS_WORKDER_PORT="443"

cat >> /etc/haproxy/haproxy.cfg << EOF
global
  log /dev/log local0
  log /dev/log local1 notice
  chroot /var/lib/haproxy
  stats timeout 30s
  user haproxy
  group haproxy
  daemon

defaults
  log global
  mode http
  option httplog
  option dontlognull
  timeout connect 5000
  timeout client 50000
  timeout server 50000

frontend ${_HAPROXY_FRONTEND_MASTER}
  bind ${_KUBE_MASTER_VIP}:${_HAPROXY_FRONTEND_MASTER_PORT}
  option tcplog
  mode tcp
  default_backend ${_HAPROXY_BACKEND_MASTER}

backend ${_HAPROXY_BACKEND_MASTER}
  mode tcp
  balance roundrobin
  option tcp-check
  server ${_KUBE_MASTER_1_NODE} ${_KUBE_MASTER_1_IP}:${_HAPROXY_BACKEND_MASTER_PORT} check fall 3 rise 2
  server ${_KUBE_MASTER_2_NODE} ${_KUBE_MASTER_2_IP}:${_HAPROXY_BACKEND_MASTER_PORT} check fall 3 rise 2
  server ${_KUBE_MASTER_3_NODE} ${_KUBE_MASTER_3_IP}:${_HAPROXY_BACKEND_MASTER_PORT} check fall 3 rise 2

frontend ${_HAPROXY_FRONTEND_HTTP_WORKDER}
   bind ${_KUBE_WORKER_VIP}:${_HAPROXY_FRONTEND_HTTP_WORKDER_PORT}
   stats uri /haproxy?stats
   default_backend ${_HAPROXY_BACKEND_HTTP_WORKDER}

backend ${_HAPROXY_BACKEND_HTTP_WORKDER}
   balance roundrobin
   server ${_KUBE_WORKER_1_NODE} ${_KUBE_WORKER_1_IP}:${_HAPROXY_BACKEND_HTTP_WORKDER_PORT} check
   server ${_KUBE_WORKER_2_NODE} ${_KUBE_WORKER_2_IP}:${_HAPROXY_BACKEND_HTTP_WORKDER_PORT} check
   server ${_KUBE_WORKER_3_NODE} ${_KUBE_WORKER_3_IP}:${_HAPROXY_BACKEND_HTTP_WORKDER_PORT} check

frontend ${_HAPROXY_FRONTEND_HTTPS_WORKDER}
   bind ${_KUBE_WORKER_VIP}:${_HAPROXY_FRONTEND_HTTPS_WORKDER_PORT}
   default_backend ${_HAPROXY_BACKEND_HTTPS_WORKDER}

backend ${_HAPROXY_BACKEND_HTTPS_WORKDER}
   balance roundrobin
   server ${_KUBE_WORKER_1_NODE} ${_KUBE_WORKER_1_IP}:${_HAPROXY_BACKEND_HTTPS_WORKDER_PORT} check
   server ${_KUBE_WORKER_2_NODE} ${_KUBE_WORKER_2_IP}:${_HAPROXY_BACKEND_HTTPS_WORKDER_PORT} check
   server ${_KUBE_WORKER_3_NODE} ${_KUBE_WORKER_3_IP}:${_HAPROXY_BACKEND_HTTPS_WORKDER_PORT} check
EOF
```

## Install keepalived and conntrack on all haproxy server
``` shell
export _PACKAGE="keepalived ipvsadm psmisc conntrack-tools"

yum install -y ${_PACKAGE}
```

## Configure keepalived and conntrack
### export environment on all haproxy server
``` shell
export _CONNTRACKD_ROOT=/etc/conntrackd
export _CONNTRACKD_CONF=${_CONNTRACKD_ROOT}/conntrackd.conf

export _KEEPALIVED_CONF=/etc/keepalived/keepalived.conf
export _KEEPALIVED_SCRIPT_ROOT=/etc/keepalived/scripts
export _KEEPALIVED_SCRIPT_CONNTRACKD=${_KEEPALIVED_SCRIPT_ROOT}/conntrackd.sh
export _KEEPALIVED_SCRIPT_IPTABLES=${_KEEPALIVED_SCRIPT_ROOT}/iptables.sh
export _KEEPALIVED_SCRIPT_HAPROXY_HEALTHCHECK=${_KEEPALIVED_SCRIPT_ROOT}/haproxy_healthcheck.sh
export _KEEPALIVED_SCRIPT_SET_STATE=${_KEEPALIVED_SCRIPT_ROOT}/set_state.sh
```
### required directory on all haproxy server
``` shell
mkdir -p ${_CONNTRACKD_ROOT} ${_KEEPALIVED_SCRIPT_ROOT}
```
### required script on all haproxy server
``` shell
# conntrackd.sh
cat >> ${_KEEPALIVED_SCRIPT_CONNTRACKD} << 'EOF'
#!/bin/bash
#
# (C) 2006-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Description:
#
# This is the script for primary-backup setups for keepalived
# (http://www.keepalived.org). You may adapt it to make it work with other
# high-availability managers.
#
# Do not forget to include the required modifications to your keepalived.conf
# file to invoke this script during keepalived's state transitions.
#
# Contributions to improve this script are welcome :).
#

CONNTRACKD_BIN=/usr/sbin/conntrackd
CONNTRACKD_LOCK=/var/lock/conntrack.lock
CONNTRACKD_CONFIG=/etc/conntrackd/conntrackd.conf

case "$1" in
  primary)
    #
    # commit the external cache into the kernel table
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -c
    if [ $? -eq 1 ]
    then
        logger "ERROR: failed to invoke conntrackd -c"
    fi

    #
    # flush the internal and the external caches
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -f
    if [ $? -eq 1 ]
    then
      logger "ERROR: failed to invoke conntrackd -f"
    fi

    #
    # resynchronize my internal cache to the kernel table
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -R
    if [ $? -eq 1 ]
    then
      logger "ERROR: failed to invoke conntrackd -R"
    fi

    #
    # send a bulk update to backups
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -B
    if [ $? -eq 1 ]
    then
        logger "ERROR: failed to invoke conntrackd -B"
    fi
    ;;
  backup)
    #
    # is conntrackd running? request some statistics to check it
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -s
    if [ $? -eq 1 ]
    then
        #
  # something's wrong, do we have a lock file?
  #
      if [ -f $CONNTRACKD_LOCK ]
  then
      logger "WARNING: conntrackd was not cleanly stopped."
      logger "If you suspect that it has crashed:"
      logger "1) Enable coredumps"
      logger "2) Try to reproduce the problem"
      logger "3) Post the coredump to netfilter-devel@vger.kernel.org"
      rm -f $CONNTRACKD_LOCK
  fi
  $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -d
  if [ $? -eq 1 ]
  then
      logger "ERROR: cannot launch conntrackd"
      exit 1
  fi
    fi
    #
    # shorten kernel conntrack timers to remove the zombie entries.
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -t
    if [ $? -eq 1 ]
    then
      logger "ERROR: failed to invoke conntrackd -t"
    fi

    #
    # request resynchronization with master firewall replica (if any)
    # Note: this does nothing in the alarm approach.
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -n
    if [ $? -eq 1 ]
    then
      logger "ERROR: failed to invoke conntrackd -n"
    fi
    ;;
  fault)
    #
    # shorten kernel conntrack timers to remove the zombie entries.
    #
    $CONNTRACKD_BIN -C $CONNTRACKD_CONFIG -t
    if [ $? -eq 1 ]
    then
      logger "ERROR: failed to invoke conntrackd -t"
    fi
    ;;
  *)
    logger "ERROR: unknown state transition"
    echo "Usage: primary-backup.sh {primary|backup|fault}"
    exit 1
    ;;
esac

exit 0
EOF

# haproxy_healthcheck.sh
cat >> ${_KEEPALIVED_SCRIPT_HAPROXY_HEALTHCHECK} << 'EOF'
#!/usr/bin/env bash

$(which killall) -0 haproxy
EOF

# iptables.sh
export _NETWORK_ADDRESS=10.10.10.251

cat >> ${_KEEPALIVED_SCRIPT_IPTABLES} << EOF
#!/bin/bash

case "$1" in
  primary)
    iptables -t nat -F
    iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to-source ${_NETWORK_ADDRESS}
  ;;
  backup)
    iptables -t nat -F
  ;;
  fault)
    iptables -t nat -F
  ;;
esac
exit 0
EOF

# set_state.sh
cat >> ${_KEEPALIVED_SCRIPT_SET_STATE} << 'EOF'
#!/bin/bash

echo instance $1 is in $2 state > /var/run/keepalive.state
EOF
```
### required script and config on sample-haproxy-001
``` shell
# conntrackd.conf
export _HAPROXY_1="10.10.10.11"
export _HAPROXY_2="10.10.10.12"

cat >> ${_CONNTRACKD_CONF} << EOF
Sync {
    Mode FTFW {
    }

    UDP {
        IPv4_address ${_HAPROXY_1}
        IPv4_Destination_Address ${_HAPROXY_2}
        Port 3780
        Interface eth0
        SndSocketBuffer 1249280
        RcvSocketBuffer 1249280
        Checksum on
    }
}

General {
    Nice -20
    HashSize 32768
    HashLimit 131072
    LogFile on
    Syslog on
    LockFile /var/lock/conntrack.lock
    UNIX {
        Path /var/run/conntrackd.ctl
        Backlog 20
    }
    NetlinkBufferSize 2097152
    NetlinkBufferSizeMaxGrowth 8388608
    Filter From Userspace {
        Protocol Accept {
            TCP
            UDP
            ICMP # This requires a Linux kernel >= 2.6.31
        }
        Address Ignore {
            IPv4_address 127.0.0.1 # loopback
            IPv4_address ${_HAPROXY_1}
        }
    }
}
EOF

# keepalived.conf
export _NETWORK_ADDRESS="10.10.10.251/24"

export _KEEPALIVED_ROUTE_ID="sample-haproxy-001"
export _KEEPALIVED_LVS_SYNC_DAEMON="haproxy 246"
export _KEEPALIVED_STATE="MASTER"
export _KEEPALIVED_PRIORITY="100"
export _KEEPALIVED_PASS="sample"
export _KEEPALIVED_VIP_1="10.10.10.19/24"
export _KEEPALIVED_VIP_2="10.10.10.20/24"

cat >> ${_KEEPALIVED_CONF} << EOF
! Configuration File for keepalived

global_defs {
    router_id ${_KEEPALIVED_ROUTE_ID}
    script_user root
    enable_script_security
    vrrp_iptables
    lvs_sync_daemon ${_KEEPALIVED_LVS_SYNC_DAEMON}
    lvs_timeouts tcp 90 tcpfin 3 udp 300
}

vrrp_script check_haproxy {
    script "/etc/keepalived/scripts/haproxy_healthcheck.sh"
    interval 2
    timeout 3
    weight 20
    rise 2
    fall 4
}

vrrp_instance ansible_kube_cluster_haproxy {
    state ${_KEEPALIVED_STATE}
    interface eth0
    virtual_router_id 246
    priority ${_KEEPALIVED_PRIORITY}
    advert_int 1
    nopreempt
    garp_master_delay 1
    notify_master "${_KEEPALIVED_SCRIPT_CONNTRACKD} primary; ${_KEEPALIVED_SCRIPT_IPTABLES} primary; ${_KEEPALIVED_SCRIPT_SET_STATE} VI_1 primary"
    notify_backup "${_KEEPALIVED_SCRIPT_CONNTRACKD} backup; ${_KEEPALIVED_SCRIPT_IPTABLES} backup; ${_KEEPALIVED_SCRIPT_SET_STATE} VI_1 backup"
    notify_fault "${_KEEPALIVED_SCRIPT_CONNTRACKD} fault; ${_KEEPALIVED_SCRIPT_IPTABLES} fault"

    authentication {
        auth_type PASS
        auth_pass ${_KEEPALIVED_PASS}
    }

    virtual_ipaddress {
        ${_NETWORK_ADDRESS} dev eth0
        ${_KEEPALIVED_VIP_1} dev eth0
        ${_KEEPALIVED_VIP_2} dev eth0
    }

    track_script {
        check_haproxy
    }
}
EOF
```
### required script and config on sample-haproxy-002
``` shell
# conntrackd.conf
export _HAPROXY_1="10.10.10.11"
export _HAPROXY_2="10.10.10.12"

cat >> ${_CONNTRACKD_CONF} << EOF
Sync {
    Mode FTFW {
    }

    UDP {
        IPv4_address ${_HAPROXY_2}
        IPv4_Destination_Address ${_HAPROXY_1}
        Port 3780
        Interface eth0
        SndSocketBuffer 1249280
        RcvSocketBuffer 1249280
        Checksum on
    }
}

General {
    Nice -20
    HashSize 32768
    HashLimit 131072
    LogFile on
    Syslog on
    LockFile /var/lock/conntrack.lock
    UNIX {
        Path /var/run/conntrackd.ctl
        Backlog 20
    }
    NetlinkBufferSize 2097152
    NetlinkBufferSizeMaxGrowth 8388608
    Filter From Userspace {
        Protocol Accept {
            TCP
            UDP
            ICMP # This requires a Linux kernel >= 2.6.31
        }
        Address Ignore {
            IPv4_address 127.0.0.1 # loopback
            IPv4_address ${_HAPROXY_2}
        }
    }
}
EOF

# keepalived.conf
export _NETWORK_ADDRESS="10.10.10.251/24"

export _KEEPALIVED_ROUTE_ID="sample-haproxy-002"
export _KEEPALIVED_LVS_SYNC_DAEMON="haproxy 246"
export _KEEPALIVED_STATE="BACKUP"
export _KEEPALIVED_PRIORITY="90"
export _KEEPALIVED_PASS="sample"
export _KEEPALIVED_VIP_1="10.10.10.19/24"
export _KEEPALIVED_VIP_2="10.10.10.20/24"

cat >> ${_KEEPALIVED_CONF} << EOF
! Configuration File for keepalived

global_defs {
    router_id ${_KEEPALIVED_ROUTE_ID}
    script_user root
    enable_script_security
    vrrp_iptables
    lvs_sync_daemon ${_KEEPALIVED_LVS_SYNC_DAEMON}
    lvs_timeouts tcp 90 tcpfin 3 udp 300
}

vrrp_script check_haproxy {
    script "/etc/keepalived/scripts/haproxy_healthcheck.sh"
    interval 2
    timeout 3
    weight 20
    rise 2
    fall 4
}

vrrp_instance ansible_kube_cluster_haproxy {
    state ${_KEEPALIVED_STATE}
    interface eth0
    virtual_router_id 246
    priority ${_KEEPALIVED_PRIORITY}
    advert_int 1
    nopreempt
    garp_master_delay 1
    notify_master "${_KEEPALIVED_SCRIPT_CONNTRACKD} primary; ${_KEEPALIVED_SCRIPT_IPTABLES} primary; ${_KEEPALIVED_SCRIPT_SET_STATE} VI_1 primary"
    notify_backup "${_KEEPALIVED_SCRIPT_CONNTRACKD} backup; ${_KEEPALIVED_SCRIPT_IPTABLES} backup; ${_KEEPALIVED_SCRIPT_SET_STATE} VI_1 backup"
    notify_fault "${_KEEPALIVED_SCRIPT_CONNTRACKD} fault; ${_KEEPALIVED_SCRIPT_IPTABLES} fault"

    authentication {
        auth_type PASS
        auth_pass ${_KEEPALIVED_PASS}
    }

    virtual_ipaddress {
        ${_NETWORK_ADDRESS} dev eth0
        ${_KEEPALIVED_VIP_1} dev eth0
        ${_KEEPALIVED_VIP_2} dev eth0
    }

    track_script {
        check_haproxy
    }
}
EOF
```
