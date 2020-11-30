#!/usr/bin/env python

import json
import os
import shutil
import subprocess
import sys
import tempfile
from time import sleep

def run(cmd, output=True, shell=True, poll=False):
    print(cmd)
    if output:
        try:
            return subprocess.check_output(cmd, shell=shell).strip()
        except:
            return ''    
    return subprocess.call(cmd, stderr=subprocess.PIPE,
        stdout=subprocess.PIPE, shell=shell)

def get_lxd_bridge_subnet(lxd_br):
    cmd = "ip a|grep %s|grep inet|awk '{print $2}'|cut -d '/' -f2" % (lxd_br)
    return run(cmd).decode("utf-8") 

def get_lxd_bridge_gateway(lxd_br):
    cmd = "ip a|grep %s|grep inet|awk '{print $2}'|cut -d '/' -f1" % (lxd_br)
    return run(cmd).decode("utf-8") 

def install_snaps_on_host():
    lxd_install_cmd = 'sudo snap install lxd --edge 2>&1'
    juju_install_cmd = 'sudo snap install juju --classic --channel=latest/edge 2>&1'
    if not is_lxd_installed():
        run(lxd_install_cmd, output=False)
    if not is_juju_installed():
        run(juju_install_cmd, output=False)

def configure_lxd():
    # check if net up and if there is storage + profile
    if get_lxd_bridge_subnet:
        print("lxdbr0 already configured...skipping")
    else:
        run("sudo lxc network create lxdbr0 bridge.mtu=9000 ipv4.address=10.32.125.1/22 ipv4.nat=true ipv6.address=none")
    storage_cmd = 'lxc storage ls|grep -v NAME|grep -v "+-----"'
    if run(storage_cmd):
        print("a storage pool is already configured....")
    else:
        run('sudo apt install zfsutils-linux -y')
        status=run("sudo lxc storage create default zfs",output=False)    
        if int(status)==1:
            run("sudo lxc storage create default dir ")
    profile_cmd = 'lxc profile list|grep maas|grep -v NAME|grep -v "+-----"'
    if run(profile_cmd):
        print("Profile already created....skipping")
    else:
        configure_lxd_profile()    


def configure_lxd_profile():
    profile_template = '''####
config:
  boot.autostart: "false" 
  raw.lxc: lxc.apparmor.profile=unconfined
  security.nesting: "true"
  security.privileged: "true"
description: Default LXD profile
devices:
  eth0:
    name: eth0
    nictype: bridged
    parent: lxdbr0
    type: nic
  root:
    path: /
    pool: default
    type: disk
'''

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(profile_template)    
    profile_create_cmd="sudo lxc profile create maas" 
    run(profile_create_cmd)
    profile_edit_cmd="sudo lxc profile edit maas < %s" % (tmp_file.name)
    run(profile_edit_cmd)

def is_lxd_installed():
    cmd = "snap list|grep lxd"
    output = run(cmd)   
    if output:
        return True
    else:
        return False

def is_juju_installed():
    cmd = "snap list|grep juju"
    output = run(cmd)   
    if output:
        return True
    else:
        return False

def create_containers():
    cleanup = "lxc delete maas-snap-1 --force && lxc delete maas-snap-2 --force && lxc delete maas-snap-3 --force"
    cmd = "lxc launch ubuntu:bionic maas-snap-1 -p maas && lxc launch ubuntu:bionic maas-snap-2 -p maas  && lxc launch ubuntu:bionic maas-snap-3 -p maas"
    try:
        run(cleanup)
    except:
        pass
    run(cmd)        

def get_container_ip(container_name):
    cmd = "lxc list %s -c 4 --format csv|awk '{print $1}'" % (container_name)
    ip = run(cmd).decode('utf-8')
    return ip 

def generate_netplan(container_name):
   # sleep(10)
    ip = get_container_ip(container_name)
    gateway = get_lxd_bridge_gateway('lxdbr0')
    cidr = get_lxd_bridge_subnet('lxdbr0')
    template = '''#####
network:
    version: 2
    ethernets:
        eth0:
            dhcp4: false
            addresses: [%s/%s]
            gateway4: %s
            nameservers:
                addresses: [8.8.8.8]
''' % (ip, cidr, gateway)   

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(template)  
    lxd_push_command = 'lxc file push %s %s/home/ubuntu/netplan.yaml' % (tmp_file.name, container_name)
    run(lxd_push_command)
    lxd_cp_command = 'lxc exec %s sudo cp /home/ubuntu/netplan.yaml /etc/netplan/50-cloud-init.yaml' % (container_name)
    lxd_netplan_apply = 'lxc exec %s sudo netplan apply' % (container_name)
    run(lxd_cp_command)
    run(lxd_netplan_apply)

def install_postges(container_name):
    pass

def configure_hosts_file():
    container_one_ip = get_container_ip('maas-snap-1')
    container_two_ip = get_container_ip('maas-snap-2')
    container_three_ip = get_container_ip('maas-snap-3')
    for i in range(1,4):
        lxd_one_cmd="lxc exec maas-snap-%s -- sh -c 'echo %s maas-snap-1.maas maas-snap-1 |sudo tee -a /etc/hosts'" % (i, container_one_ip)
        lxd_two_cmd="lxc exec maas-snap-%s -- sh -c 'echo %s maas-snap-2.maas maas-snap-2 |sudo tee -a /etc/hosts'" % (i ,container_two_ip)
        lxd_three_cmd="lxc exec maas-snap-%s -- sh -c 'echo %s maas-snap-3.maas maas-snap-3 |sudo tee -a /etc/hosts'" % (i, container_three_ip)
        run(lxd_one_cmd)
        run(lxd_two_cmd)
        run(lxd_three_cmd)


configure_hosts_file()

