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
    - [Configure firewalld on all haproxy server](#Configure-firewalld-on-all-haproxy-server)
  - [Tuning systemc parameters on all kubernetes server](#Tuning-systemc-parameters-on-all-kubernetes-server)
  - [Install kubelet on all kubernetes server](#Install-kubelet-on-all-kubernetes-server)
  - [Initial Kubernetes Cluster](#Initial-Kubernetes-Cluster)
    - [Initail kubernetes master on sample-kube-master-001](#Initail-kubernetes-master-on-sample-kube-master-001)
    - [Get certificate_key on sample-kube-master-001](#Get-certificate_key-on-sample-kube-master-001)
    - [Remove temp file](#Remove-temp-file)
    - [Get Kubernetes API Config](#Get-Kubernetes-API-Config)
    - [Initial CNI network](#Initial-CNI-network)
    - [Join Kubernetes Cluster on other Master Node](#Join-Kubernetes-Cluster-on-other-Master-Node)
  - [Kubernetes Dashbaord](#Kubernetes-Dashbaord)
  - [Metrics Server](#Metrics-Server)
  - [Kubernetes Nginx Ingress](#Kubernetes-Nginx-Ingress)
  - [Kubernetes MetalLB](#Kubernetes-MetalLB)

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

vrrp_instance sample_haproxy {
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

vrrp_instance sample_haproxy {
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

## Configure firewalld on all haproxy server
``` shell
firewall-cmd --direct --permanent --add-rule ipv4 filter INPUT 0 --in-interface eth0 --destination 224.0.0.18 --protocol vrrp -j ACCEPT
firewall-cmd --reload
```

## Tuning systemc parameters on all kubernetes server
``` shell
export _MODULES_BR_NETFILTER="/etc/modules-load.d/br_netfilter.conf"
export _SYSCTL_CONF="/etc/sysctl.d/kubernetes.conf"
export _SECURITY_LIMITS="/etc/security/limits.d/kubernetes.conf"

cat >> ${_MODULES_BR_NETFILTER} << EOF
br_netfilter
EOF

cat >> ${_SYSCTL_CONF} << EOF
net.ipv4.ip_forward=1
net.bridge.bridge-nf-call-ip6tables=1
net.bridge.bridge-nf-call-iptables=1
EOF

cat >> ${_SECURITY_LIMITS} << EOF
*  soft  nofile  1000000
*  hard  nofile  1000000
*  soft  nproc   1000000
*  hard  nproc   1000000
EOF
```

## Install kubelet on all kubernetes server
``` shell
export _KUBE_REPO="/etc/yum.repos.d/kubernetes.repo"
export _PACKAGE="kubelet-1.17.0-0 kubeadm-1.17.0-0 kubectl-1.17.0-0"

cat >> ${_KUBE_REPO} << EOF
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF

yum install -y ${_PACKAGE}
```

## Initail kubernetes master on sample-kube-master-001
``` shell
export _WORK_DIR=~/temp
export _KUBEADM_CONFIG_FILE="kubeadm-config.yaml"
export _KUBE_TOKEN=$(kubeadm token generate)
export _KUBE_HAPROXY="sample-haproxy"
export _KUBE_HAPROXY_IP="10.10.10.19"
export _KUBE_HAPROXY_PORT="6443"
export _KUBE_CLUSTER_NAME="sample-kube-cluster"
export _KUBE_NODEREGISTRATION_NAME="sample-kube-master-001"
export _KUBE_KUBERNETES_VERSION="v1.17.0"
export _KUBE_SERVICE_SUBNET="10.96.0.0/12"
export _KUBE_POD_SUBNET="10.244.0.0/16"
export _KUBE_ADVERTISE_ADDRESS="10.10.10.13"

mkdir -p ${_WORK_DIR}
cd ${_WORK_DIR}

cat > ${_KUBEADM_CONFIG_FILE} << END
apiVersion: kubeadm.k8s.io/v1beta2
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: ${_KUBE_TOKEN}
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: ${_KUBE_ADVERTISE_ADDRESS}
  bindPort: 6443
nodeRegistration:
  criSocket: /var/run/dockershim.sock
  name: ${_KUBE_NODEREGISTRATION_NAME}
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
---
apiServer:
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta2
certificatesDir: /etc/kubernetes/pki
clusterName: ${_KUBE_CLUSTER_NAME}
controlPlaneEndpoint: "${HA_PROXY}:${HA_PROXY_PORT}"
controllerManager: {}
dns:
  type: CoreDNS
etcd:
  local:
    dataDir: /var/lib/etcd
imageRepository: k8s.gcr.io
kind: ClusterConfiguration
kubernetesVersion: ${_KUBE_KUBERNETES_VERSION}
networking:
  dnsDomain: ${_KUBE_CLUSTER_NAME}.local
  serviceSubnet: ${_KUBE_SERVICE_SUBNET}
  podSubnet: ${_KUBE_POD_SUBNET}
scheduler: {}
END

cat >> /etc/hosts << EOF

${_KUBE_HAPROXY_IP} ${_KUBE_HAPROXY}
EOF

kubeadm init --config=${_KUBEADM_CONFIG_FILE}
```

#### Output
``` shell
Your Kubernetes control-plane has initialized successfully!

To start using your cluster, you need to run the following as a regular user:

  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

You can now join any number of control-plane nodes by copying certificate authorities
and service account keys on each node and then running the following as root:

  kubeadm join sample-haproxy:6443 --token rvx4te.nxupiekihv8j03p7 \
    --discovery-token-ca-cert-hash sha256:ba59363378a9286d59b9ffccc9c0bd2d908d339b02956f139de03b2edee51681 \
    --control-plane

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join sample-haproxy:6443 --token rvx4te.nxupiekihv8j03p7 \
    --discovery-token-ca-cert-hash sha256:ba59363378a9286d59b9ffccc9c0bd2d908d339b02956f139de03b2edee51681
```
- #### Copy `--token` value `rvx4te.nxupiekihv8j03p7` (export _KUBE_TOKEN=$(kubeadm token generate))
- #### Copy `--discovery-token-ca-cert-hash` value `sha256:ba59363378a9286d59b9ffccc9c0bd2d908d339b02956f139de03b2edee51681` (export DISCOVERY_TOKEN_CA_CERT_HASH=ba59363378a9286d59b9ffccc9c0bd2d908d339b02956f139de03b2edee51681)

### Get certificate_key on sample-kube-master-001
``` shell
kubeadm init phase upload-certs --upload-certs
```

#### Output
``` shell
W0114 14:20:56.652884   18849 validation.go:28] Cannot validate kubelet config - no validator is available
W0114 14:20:56.652957   18849 validation.go:28] Cannot validate kube-proxy config - no validator is available
[upload-certs] Storing the certificates in Secret "kubeadm-certs" in the "kube-system" Namespace
[upload-certs] Using certificate key:
12e3424d61ba957db5faa5bdd436874b5edd77984cac4e6789a49d7665046fd4
```
- #### Copy `12e3424d61ba957db5faa5bdd436874b5edd77984cac4e6789a49d7665046fd4` (export CERTIFICATE_KEY=12e3424d61ba957db5faa5bdd436874b5edd77984cac4e6789a49d7665046fd4)

### Remove temp file
``` shell
rm -f ${_WORK_DIR}/${_KUBEADM_CONFIG_FILE}
```

### Get Kubernetes API Config
``` shell
cat /etc/kubernetes/admin.conf
```

#### `Output`
``` yaml
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN5RENDQWJDZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJd01ERXhOREEyTVRrME5Wb1hEVE13TURFeE1UQTJNVGswTlZvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTTIvCnRIT21tOVRyZW1MbGdrQTdqWlFYODVRbVlMdlJQWGhPbkJhT1JMRkZJQkI1bEFLQTVDSFBuQzZ6bDc0QWUyRkIKeU1WVEo1OXFMbDB1T3FJZkowNFJJalBNNDg2d0VzNWhUd3dEQmhwU3JlTHVQUWVJYURpSlNJd0lqRVY3N2V1UAp2WXJqZTFmVTJTbXkxNG5rMndvaHlJVUJwcXpSNTdMZmhVS1RHamQ3NGFEVU1wRThkY0ZpWG9seUJZSk41SlQwClZhRG45S0ZjRW80aTVkbE94VnVNRWRkOW92dGx2MlE0VDErZjdTOVIzN1A0YTgzZlFPb0grRk90RTZZakJINlkKOEkxaEt5a2lMQ0tXazZaQXVXUmxRSmF5YnFHRzdIK01LdnV1M3NheFZTd0RqNklZRmlXbktNUkxXQU5Sbnh1cwpTRzRxanQ0NHVlRTc4cHJIZFowQ0F3RUFBYU1qTUNFd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFLK0ViTWhMQzZQR2hIcTlTYkxGdjMzUEN4ZTgKeWNETnY5eXY1andxd3dxNThNOWRnV3plcW51NVhORE5WT21qYWErS04yeEJkZFN2d2ZLZTRjenRkYmRwdjh4ZwpNOXFUaHh2NkM3V3ovSkpjU1k0c3FaMk1rTEhSdlRPZEF4NWdHZ0h5YXJBVm1xand1dzJTRHVaU3huUXQ2NnBDCmVvczl5M1p5cnU1NXBwTmEvdVVIUlZTM0VYV1VDakh0UVBrZm9lV0h3bllKZUZ6Vm94eEZNMVJHaklWUHIyYmsKbVBQOUZTaEZ5TDE3eGsvSVlmSkZiMXl1cjZEUnc5RmdFS2hlZENkQlBXbVN2dElxT1pta1ByQTk4ZDM1UWtIVAo0UzU5TFNFb1dSR1BkeVI3T3krUFZpaFl6NDV4N3BFZ3BXTVVSenRSYTRtWnIvTmx4bXNMZXJWb1ZNdz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    server: https://sample-haproxy:6443
  name: sample-kube-cluster
contexts:
- context:
    cluster: sample-kube-cluster
    user: kubernetes-admin
  name: kubernetes-admin@sample-kube-cluster
current-context: kubernetes-admin@sample-kube-cluster
kind: Config
preferences: {}
users:
- name: kubernetes-admin
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM4akNDQWRxZ0F3SUJBZ0lJREdETWtkblhCRll3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TURBeE1UUXdOakU1TkRWYUZ3MHlNVEF4TVRNd05qRTVORGhhTURReApGekFWQmdOVkJBb1REbk41YzNSbGJUcHRZWE4wWlhKek1Sa3dGd1lEVlFRREV4QnJkV0psY201bGRHVnpMV0ZrCmJXbHVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXV6ZHFXblRhLzBkL1VmU2oKek56djhQTG43OHU3R21QL2Y3b2pvZ1Z5aDFjU0RBdld5Q2h0Myt2ZFdyRDZwK1VYYTdwOHVzRCsvcFZodUdobgpCdTFSZ3MzK1QxaWhybVFCZys1cTVyb1B2aEpQQnowNllYUHVLREFsT2NjNkRlclUrdGo2cGdqbnNwbTlyRU00CnpXR29MbU1oTzB5OHBXcndMZEFGWXQ4OTJ1WjhJcVRNZzgzRGplZ1NLem0rSklEdTJFZUJoVy81NHJXWnA3Qk8KU01iRVVZVmRoVzFkcGlWYnA3WExZdWUxUXFnT2FDbUM1c2c0RVRBQklBZEgyVDFIdENoaVpWbzRHSkphNlFrcwpWSnNpQ3Q2a3Avd21TTGEzRHRXNXZab3ZqcHR2WnFDTFRHb1JXK2VOUGN1cUk5VEFvcFlCNGRoSVdtSmhqbzdlCmZrblpHUUlEQVFBQm95Y3dKVEFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUgKQXdJd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFJT0lib2FRVUhYWUE5M0FvWjBMWGxkcS84MkI2ZHcwSFlIZwpBdkRmTHpTcENGWml4OHNCcmh5YjdzeTlKOWRjY3VrcHpXMmlPaURmMm16b21RSkJiVEVGdG9hVlRLRUUwU2J4CjEwOERPNkV3MjJaRmFheTdscktnMEllTkRmajd1N3hINmIyakZod3dEY1E1MHNKU2lYVkVyMWxvelgvbTV2YUoKV3NycWZpVFlHR3hWTXFRd0pIam1XYmFiQ0tLVi9td0ZqWlVhSk5hckhFTnRHYm5XdkdGRmVQZkNmMEpPRTlhYwpUZDBDR3hmSVdtb1BwdURuR0drUGpHK3pNMmlFZzZRTmlsZnV2QTBGeDBZcnBtcFJzN2dsNGhqVEFDVDE1VDA3CjZoYWRkZmhzcGJyRC8xMG5nSkpXRGRscEhGV2VoclhOQWpmNXAvR2FESjNySDJ5Smt1RT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdXpkcVduVGEvMGQvVWZTanpOenY4UExuNzh1N0dtUC9mN29qb2dWeWgxY1NEQXZXCnlDaHQzK3ZkV3JENnArVVhhN3A4dXNEKy9wVmh1R2huQnUxUmdzMytUMWlocm1RQmcrNXE1cm9QdmhKUEJ6MDYKWVhQdUtEQWxPY2M2RGVyVSt0ajZwZ2puc3BtOXJFTTR6V0dvTG1NaE8weThwV3J3TGRBRll0ODkydVo4SXFUTQpnODNEamVnU0t6bStKSUR1MkVlQmhXLzU0cldacDdCT1NNYkVVWVZkaFcxZHBpVmJwN1hMWXVlMVFxZ09hQ21DCjVzZzRFVEFCSUFkSDJUMUh0Q2hpWlZvNEdKSmE2UWtzVkpzaUN0NmtwL3dtU0xhM0R0VzV2Wm92anB0dlpxQ0wKVEdvUlcrZU5QY3VxSTlUQW9wWUI0ZGhJV21KaGpvN2Vma25aR1FJREFRQUJBb0lCQUJoWGJ5dU5yLytyQXlIYgp4Z1JYNFphWmJwQ2VFNWl0MGNXQXBTdG11K3BlNXNqTUxVUGZCZElzYjU1Z0RtY1FBVWlQZWJJcWI3MFlIUm1GCjhZZFVDZG9SQUhTK21GNzlQN2t3b1pPWU0zM0tFWjVtVnBYZkplTHh4NVZJa3dMR09xVFcyMWdGSm1MeFhGanUKY0k4N21FdFh0alZvbDhxR0tlNDY4c2hWTUV5cW5CZ3ZqMjkrd2JPeTJ2TzIyM25Gd0htUG8xLzZKNC9vL0JIZQpkcG9NZkNmWSs4ZE0ycExjZGRmYVIxV1RuZUdIalY5UGIyUkFOYkNRTWFVNVRpaE1sOGZnMmJHSXErWXkrOUlTCnJUNU1qUG5WMnNwQ3ZrMHdJMkdnTHpybUFoTE0rWjhiSXRVZVg0YWN1K2dKRWxzRDd2cGJhSW5ZSlFsWHcwS3cKYjNqczhBRUNnWUVBMDBBNUdVQzNrbFFSM0s2c1NWYWpMWkRuSTUxclZTMnBkWnBKdEdheU9KUlpDTEZYb0d5Ygp1WHYvanJLbFQxNnc4dkVWejRLVHNWVkFaT1V4cW9nZnN4SXo0R3NjQmwwaDdSQ0MvMFFUWGVRT1lyQlJNeHpiCktmbkQzWW9ob3gySUFiVGJ0U2FybmZXdzlhSXc4YmNoUUc0YUZ5OW43R1BHTTFHSVpETHNXZ0VDZ1lFQTR0L1kKNjJHcVJUaWVSMUN4NUtxOUZ5SXQ1VkxXTGhnR0thekQzeTJMOWxwaTN4UnJQeHhzcmpWeE9NSFdFK1hJN3ZtWApZOWlMbUF2RHpQcE5lZkFGMEZoRkNYWTRuNHQybmhCVWNkV3VkREhJMFhPTkFuN2F1UXI4Ky93SW00OHRqYmZmCi8yT3Y4MU1aQzBCN3UrQ0NoN3k0S0RBMXp1VVNIT3QzYjZYdkR4a0NnWUJCdkFWSWQxdm4rNk1IUVk4NHp1MjkKMnc0aGhmV0ZMczFCVy80OVZZdDFrYXZXeWFCVHVoZ0c4cS9HRG83a0VMb05Ecm5UdFhVUnhFNWlWdk5LZGtzdQo1S1loMmhLQlpHK1BIZ2sxTjFDemNhaU1Td01wWFh4UkpuZ3RNck5lMTJ5ZjQxQk9vVGJiMHp6NllqcktyRXA3Cml3Y3hXYjREejlRMzJkSVFJOHhxQVFLQmdRQ2pPZWZJR2FFMllqREdJRkdNc2lhUE1VRVIvNUltNFpQMWdkMysKZ0xkMUM3eWN3UVVVQi9CTk9oZjJmTWIzMDlmSHozelRFaVlFdzFvZzdHaTNkUy9Kb09neWtZTFZqckpOc0hRQQozbnJBRUYxcURCZUVseDNvQ2ZiUG1KbmN5WnM5bmZBanYyWUV5MkYyVGZOM3pXUThJbFBnWGljb2JuaWtvK2h2ClJGUUZhUUtCZ0ZQdS9GMG5wMVptQ212WWxBYzNzQnBuQklmQ0ovSUdJRUJ3ekNLRHBad0kxVEtSdE1EV1JzdmcKY1VKejBRYjRhcXhNdkowS0dzQTRjWm5nZVdwbGNOM28yMnNDcmRUQ29XS1kzWW5oNTBKUitFbTUzOERabEFregpUQ3BJV0tvQmxmT2U1bkRtc1dTQUFVejJCOE5KZFZhclhYTXBrTng3MUhrSTdSVTJkUDBXCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==
```
- #### Copy Content to Your Local ~/.kube/config

### Initial CNI network
``` shell
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
```

## Join Kubernetes Cluster on other Master Node
``` shell
export _KUBE_HAPROXY="sample-haproxy"
export _KUBE_HAPROXY_IP="10.10.10.19"
export _KUBE_HAPROXY_PORT="6443"
export _KUBE_TOKEN='rvx4te.nxupiekihv8j03p7'
export _KUBE_DISCOVERY_TOKEN_CA_CERT_HASH='sha256:ba59363378a9286d59b9ffccc9c0bd2d908d339b02956f139de03b2edee51681'
export _KUBE_CERTIFICATE_KEY='12e3424d61ba957db5faa5bdd436874b5edd77984cac4e6789a49d7665046fd4'

cat >> /etc/hosts << EOF

${_KUBE_HAPROXY_IP} ${_KUBE_HAPROXY}
EOF

kubeadm join ${_KUBE_HAPROXY}:${_KUBE_HAPROXY_PORT} --token ${_KUBE_TOKEN} \
--discovery-token-ca-cert-hash ${_KUBE_DISCOVERY_TOKEN_CA_CERT_HASH} \
--control-plane \
--certificate-key ${_KUBE_CERTIFICATE_KEY}
```

## Join Kubernetes Cluster on Worker Node
``` shell
export _KUBE_HAPROXY="sample-haproxy"
export _KUBE_HAPROXY_IP="10.10.10.19"
export _KUBE_HAPROXY_PORT="6443"
export _KUBE_TOKEN='rvx4te.nxupiekihv8j03p7'
export _KUBE_DISCOVERY_TOKEN_CA_CERT_HASH='sha256:ba59363378a9286d59b9ffccc9c0bd2d908d339b02956f139de03b2edee51681'

cat >> /etc/hosts << EOF

${_KUBE_HAPROXY_IP} ${_KUBE_HAPROXY}
EOF

kubeadm join ${_KUBE_HAPROXY}:${_KUBE_HAPROXY_PORT} --token ${_KUBE_TOKEN} \
--discovery-token-ca-cert-hash ${_KUBE_DISCOVERY_TOKEN_CA_CERT_HASH}
```

## Kubernetes Dashbaord
## Install
``` shell
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0-beta8/aio/deploy/recommended.yaml
```

## Create Admin Service Account
### Create Service Account
``` shell
cat << EOF | kubectl create -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kube-system
EOF
```

### Describe cluster-admin Cluster Roles
``` shell
kubectl describe clusterrole/cluster-admin
```

#### Output
``` shell
Name:         cluster-admin
Labels:       kubernetes.io/bootstrapping=rbac-defaults
Annotations:  rbac.authorization.kubernetes.io/autoupdate: true
PolicyRule:
  Resources  Non-Resource URLs  Resource Names  Verbs
  ---------  -----------------  --------------  -----
  *.*        []                 []              [*]
             [*]                []              [*]
```

### Grant cluster-admin roles for admin-user
``` shell
cat << EOF | kubectl create -f -
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kube-system
EOF
```

## Vefiry admin-user Grant
``` shell
kubectl describe ClusterRoleBinding/admin-user
```

## Get admin-user token
``` shell
kubectl describe secret -n kube-system $(kubectl get secret -n kube-system -o name | grep admin-user | awk -F '/' '{ print $NF }') | awk '$1=="token:" { print $2 }'
```

#### Output
``` shell
eyJhbGciOiJSUzI1NiIsImtpZCI6IjdQYlB1bWhQUjZ0V3ZpMVFUeldrR2ZvVjZmTjhjWDZGSGE4VFlWbzFDeUkifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJhZG1pbi11c2VyLXRva2VuLTV2NTh0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImFkbWluLXVzZXIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiI2YTBlODRmNS04MzlhLTQyNTEtOTFmZi1iN2Q1NDM3NzFkYTUiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06YWRtaW4tdXNlciJ9.LEQmHMxchmb06C2AkpSVys39oce8I5zQxGBXFa9hmB7R1IWCxM4BYoHWc_L9ooYodxIlN63SJ6wVtgxScuHv1TZfnwDrMzzVz6N2TOOyjUW_2DQvGfgYSrykVG2_yRlm8txLYQZiRybtNMaYXifcOWOC87ryBrpzYRotUOjXAQToyfE5NnDtJR3mwDFEXXQwSmya11WwWQ4zmyriaQY6D3LC0Uy376sKPArVtiZRuKwFh11uQn_IuCUTbHqMmz6ZSkiwa23-dVrXEVrx5qfh9fNC3GhWEeVBK_3EwRx0b5f-KynoIjsq4zZ8IXD52Jc-ReqYd2KNqb92OBUiwCtFfw
```

## Create Kubernetes Dashbaord Proxy
``` shell
kubectl proxy
```

## Open Browser
### [Dashboard](http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/)
#### `Paste Token above`

## Metrics Server
## At All Kubernetes Nodes
### Enable serverTLSBootstrap in kubelet configuration
``` shell
echo "serverTLSBootstrap: true" >> /var/lib/kubelet/config.yaml
systemctl restart kubelet
```

## Approve certificate
``` shell
export _KUBE_CSR=$(kubectl get csr | egrep -i 'pending$' | awk '{ print $1 }')
for i in ${_KUBE_CSR}; do kubectl certificate approve ${i}; done
```

## Initial metrics-server
``` shell
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/download/v0.3.6/components.yaml
kubectl -n kube-system patch deployment metrics-server --patch '{"spec": {"template": {"spec": {"hostNetwork": true}}}}'
```

### Check apiservice
``` shell
kubectl -n kube-system get apiservice v1beta1.metrics.k8s.io
```

#### Output
``` shell
NAME                     SERVICE                      AVAILABLE   AGE
v1beta1.metrics.k8s.io   kube-system/metrics-server   True        19s
```

### Check node resource usage
``` shell
kubectl top nodes
```

#### Output
``` shell
NAME                     CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
sample-kube-master-001   115m         5%     1053Mi          64%
sample-kube-master-002   90m          4%     1029Mi          62%
sample-kube-master-003   86m          4%     1020Mi          62%
sample-kube-worker-001   35m          0%     864Mi           5%
sample-kube-worker-002   35m          0%     886Mi           5%
sample-kube-worker-003   34m          0%     884Mi           5%
```

## Kubernetes Nginx Ingress
``` shell
git clone https://github.com/nginxinc/kubernetes-ingress
cd kubernetes-ingress/deployments
git checkout v1.7.2

# Configure RBAC
kubectl apply -f common/ns-and-sa.yaml
kubectl apply -f rbac/rbac.yaml

# Create Common Resources
kubectl apply -f common/default-server-secret.yaml
kubectl apply -f common/nginx-config.yaml
kubectl apply -f common/vs-definition.yaml
kubectl apply -f common/vsr-definition.yaml
kubectl apply -f common/ts-definition.yaml
kubectl apply -f common/gc-definition.yaml
kubectl apply -f common/global-configuration.yaml

# Deploy the Ingress Controller
kubectl apply -f daemon-set/nginx-ingress.yaml
```

## Kubernetes MetalLB
## Apply MetalLB Service
``` shell
kubectl apply -f https://raw.githubusercontent.com/google/metallb/v0.8.3/manifests/metallb.yaml
```

## Assign IP Range (Layer 2)
``` shell
export _KUBE_IP_RANGE="10.10.10.21-10.10.10.30"
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      - ${_KUBE_IP_RANGE}
EOF
```
