#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
import sys
import tempfile
from time import sleep
from random import randint

MAAS_VIP = ''

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
    configure_snappy_cmd = 'sudo snap install core18 && sudo snap install snapd'
    lxd_install_cmd = 'sudo snap install lxd --edge'
    juju_install_cmd = 'sudo snap install juju --classic --channel=latest/edge'
    if not is_lxd_installed():
        run(configure_snappy_cmd)
        run(lxd_install_cmd)
    if not is_juju_installed():
        run(juju_install_cmd)

def configure_lxd(username=None):
    # check if net up and if there is storage + profile
    if get_lxd_bridge_subnet('lxdbr0'):
        print("lxdbr0 already configured...skipping")
    else:
        run("lxc network create lxdbr0 bridge.mtu=9000 ipv4.address=10.32.125.1/22 ipv4.nat=true ipv6.address=none")
    storage_cmd = 'lxc storage ls|grep -v NAME|grep -v "+-----"'
    if run(storage_cmd):
        print("a storage pool is already configured....")
    else:
        run('sudo apt install zfsutils-linux -y')
        status=run("lxc storage create default zfs",output=False)    
        if int(status)==1:
            run("lxc storage create default dir ")
    profile_cmd = 'lxc profile list|grep maas|grep -v NAME|grep -v "+-----"'
    if run(profile_cmd):
        print("Profile already created....skipping")
    else:
        configure_lxd_profile(username)    

def get_user_info():
   pass

def configure_maas_snaps():
    sleep(30)
    pg_sql_cleanup()
    gateway = get_lxd_bridge_gateway('lxdbr0')
    subnet_ls = gateway.split('.')
    subnet_ls[3] = '253'
    vip_addr = '.'.join(subnet_ls)  
    secret = ''     
    for i in range(1,4):
        maas_url = 'http://' + get_container_ip('maas-snap-%s' %i ) + ':80/MAAS'
        run('lxc exec maas-snap-%s -- sh -c "sudo maas init region+rack --database-uri postgres://maas:password@%s/maasdb --maas-url %s --force"' % (i,vip_addr,maas_url) )
        sleep(30)
                
        if i == 3:
            run('lxc exec maas-snap-3 sudo crm resource cleanup pgsql')

def configure_kvm_host():
    # run at the end, so it doesn't muck with get_ip function
    pass
    template='''
<network>
  <name>maas</name>
  <forward mode='nat'/>
  <bridge name='virbr-maas' stp='on' delay='0'/>
  <mac address='52:54:00:02:83:8a'/>
  <ip address='192.168.124.1' netmask='255.255.255.0'>
  </ip>
</network>'''
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(template)
    cmd = 'virsh net-create %s' % (tmp_file.name)
    run(cmd)

def configure_maas_network_on_containers():
    for i in range(1,4):
        cmd = 'lxc config device add maas-snap-%s eth1 nic nictype=bridged parent=virbr-maas' % i 
        run(cmd)
        run('lxc exec maas-snap-%s sudo netplan apply' % i)
    sleep(60)
    pg_sql_cleanup()


def configure_lxd_profile(lp_id):
    profile_template = '''####
config:
  raw.lxc: |-
    lxc.mount.auto=sys:rw
    lxc.cgroup.devices.allow = c 10:237 rwm
    lxc.cgroup.devices.allow = b 7:* rwm
  security.nesting: "true"
  boot.autostart: "false" 
  user.user-data: |
    #cloud-config
    package_update: true
    packages:
      - openssh-server
      - haproxy
      - corosync
      - pacemaker
      - pcs
      - crmsh
      - postgresql
      - squashfuse
    snap:
      commands:
        00: ['install', 'maas-cli']
        01: ['install', 'maas']
    ssh_import_id:
       - lp:%s    
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
  loop0:
    path: /dev/loop0
    type: unix-block
  loop1:
    path: /dev/loop1
    type: unix-block
  loop2:
    path: /dev/loop2
    type: unix-block
  loop3:
    path: /dev/loop3
    type: unix-block
  loop4:
    path: /dev/loop4
    type: unix-block
  loop5:
    path: /dev/loop5
    type: unix-block
  loop6:
    path: /dev/loop6
    type: unix-block
  loop7:
    path: /dev/loop7
    type: unix-block    
''' % (lp_id)

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(profile_template)    
    profile_create_cmd="lxc profile create maas" 
    run(profile_create_cmd)
    profile_edit_cmd="lxc profile edit maas < %s" % (tmp_file.name)
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

def is_maas_installed():
    for i in range(1,4):
        cmd = "lxc exec maas-snap-%s snap list|grep maas" % (i)
        output = run(cmd)   
        if output:
            continue
        else:
            return False
    return True        

def is_postgres_installed():
    for i in range(1,4):
        cmd = "lxc exec maas-snap-%s -- sh -c 'dpkg -l|grep post'" % (i)
        output = run(cmd)   
        if output:
            continue
        else:
            return False
    return True    


def is_haproxy_installed():
    for i in range(1,4):
        cmd = "lxc exec maas-snap-%s -- sh -c 'dpkg -l|grep haproxy'" % (i)
        output = run(cmd)   
        if output:
            continue
        else:
            return False
    return True      

def is_haproxy_installed():
    for i in range(1,4):
        cmd = "lxc exec maas-snap-%s -- sh -c 'dpkg -l|grep corosync'" % (i)
        output = run(cmd)   
        if output:
            continue
        else:
            return False
    return True    

def create_containers():
    cleanup = "lxc delete maas-snap-1 --force && lxc delete maas-snap-2 --force && lxc delete maas-snap-3 --force"
    cmd = "lxc launch ubuntu:bionic maas-snap-1 -p maas && lxc launch ubuntu:bionic maas-snap-2 -p maas  && lxc launch ubuntu:bionic maas-snap-3 -p maas"
    try:
        run(cleanup)
    except:
        pass
    run(cmd)        

def get_container_ip(container_name):
    #cmd = "lxc list %s -c 4 --format csv|awk '{print $1}'" % (container_name)
    cmd = '''lxc list %s -c 4 --format csv |cut -d "\\"" -f2|awk '{print $1}'|head -1''' % container_name
    ip = run(cmd).decode('utf-8')
    return ip 

def configure_haproxy():
    container_one_ip = get_container_ip('maas-snap-1')
    container_two_ip = get_container_ip('maas-snap-2')
    container_three_ip = get_container_ip('maas-snap-3')
    template = '''###
frontend maas
    bind    *:80
    retries 3
    option  redispatch
    option  http-server-close
    default_backend maas

backend maas
    timeout server 90s
    balance source
    hash-type consistent
    server localhost localhost:5240 check
    server maas-api-1 %s:5240 check
    server maas-api-2 %s:5240 check
    server maas-api-3 %s:5240 check''' % (container_one_ip, container_two_ip, container_three_ip)

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(template)  

    for i in range(1,4):
        lxd_push_command = 'lxc file push %s %s/home/ubuntu/haproxy.conf' % (tmp_file.name, 'maas-snap-%s' % i)
        run(lxd_push_command)
        lxd_cp_command = 'lxc exec %s -- sh -c "sudo cp /home/ubuntu/haproxy.conf /etc/haproxy/haproxy.cfg"' % ('maas-snap-%s' % i)
        lxd_haproxy_reset = 'lxc exec %s -- sh -c "sudo systemctl enable haproxy && systemctl restart haproxy"' % ('maas-snap-%s' % i)
        run(lxd_cp_command)
        run(lxd_haproxy_reset)

def generate_netplan(container_name):
    # wait at least a minute and a half while cloud-init does its dirty work
    ip = get_container_ip(container_name)
    gateway = get_lxd_bridge_gateway('lxdbr0')
    cidr = get_lxd_bridge_subnet('lxdbr0')
    eth1_ip = '192.168.124.' + str(randint(2,254))
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
        eth1:
            dhcp4: false
    bridges:
        br0:
            dhcp4: false
            addresses: [%s/24]
            nameservers:
                addresses: [%s]
            interfaces: [eth1]                        
''' % (ip, cidr, gateway, eth1_ip, eth1_ip)   

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(template)  
    lxd_push_command = 'lxc file push %s %s/home/ubuntu/netplan.yaml' % (tmp_file.name, container_name)
    run(lxd_push_command)
    lxd_cp_command = 'lxc exec %s sudo cp /home/ubuntu/netplan.yaml /etc/netplan/50-cloud-init.yaml' % (container_name)
    lxd_netplan_apply = 'lxc exec %s sudo netplan apply' % (container_name)
    run(lxd_cp_command)
    run(lxd_netplan_apply)

def configure_postgres():
    # disable systemd unit, confiugre postgres.conf, pga_hba.conf
    postgres_conf_template = '''###
listen_addresses = '*'
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'
log_timezone = 'Etc/UTC'
stats_temp_directory = '/var/run/postgresql/10-main.pg_stat_tmp'
datestyle = 'iso, mdy'
timezone = 'Etc/UTC'
default_text_search_config = 'pg_catalog.english'
wal_level = hot_standby
archive_mode = off
max_wal_senders = 10
wal_keep_segments = 256
hot_standby = on
hot_standby_feedback = on    
restart_after_crash = off
max_connections = 300
synchronous_commit = on
#data_directory = '/var/lib/postgresql/10/main/'
'''
    container_one_ip = get_container_ip('maas-snap-1')
    container_two_ip = get_container_ip('maas-snap-2')
    container_three_ip = get_container_ip('maas-snap-3')
    gateway = get_lxd_bridge_gateway('lxdbr0')
    cidr = get_lxd_bridge_subnet('lxdbr0')
    subnet_ls = gateway.split('.')
    subnet_ls[3] = '0'
    subnet_addr = '.'.join(subnet_ls) + '/' + cidr
    # initialize maas db before doing ha
    run('''lxc exec maas-snap-1 -- sh -c "sudo -u postgres psql -c \\"CREATE USER \\"maas\\" WITH ENCRYPTED PASSWORD 'password'\\""''')
    run("""lxc exec maas-snap-1 -- sh -c 'sudo -u postgres createdb -O "maas" "maasdb"'""")
    run('lxc exec maas-snap-1 sudo systemctl restart postgresql')    
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(postgres_conf_template)

    for i in range(1,4):
        # configure postgres.conf
        lxd_push_command = 'lxc file push %s maas-snap-%s/home/ubuntu/postgresql.conf' % (tmp_file.name, i)
        lxd_cp_command = 'lxc exec maas-snap-%s sudo cp /home/ubuntu/postgresql.conf /etc/postgresql/10/main/postgresql.conf' % (i)
        run(lxd_push_command)
        run(lxd_cp_command)
        # configure pg_hba.conf
        replication_cmd="lxc exec maas-snap-%s -- sh -c 'echo host    replication    postgres     %s    trust |sudo tee -a /etc/postgresql/10/main/pg_hba.conf'"  \
        % (i, subnet_addr)
        access_cmd="lxc exec maas-snap-%s -- sh -c 'echo host    maasdb    maas     %s   md5 |sudo tee -a /etc/postgresql/10/main/pg_hba.conf'"  \
        % (i, subnet_addr)  
        run(replication_cmd)
        run(access_cmd)
        run("""lxc exec maas-snap-%s -- sh -c 'sed -i "s/\\^node/node/g" /usr/lib/ocf/resource.d/heartbeat/pgsql'""" % i)
        # configure pg stat
        run('''lxc exec maas-snap-%s -- sh -c \'echo "d /var/run/postgresql/10-main.pg_stat_tmp 2750 postgres postgres" > /etc/tmpfiles.d/1-main.pg_stat_tmp.conf\'''' % i)
        run("lxc exec maas-snap-%s systemd-tmpfiles --create" % i)

        if i == 1:
            copy_cmd = "lxc exec maas-snap-1 -- sh -c 'sudo cp /etc/postgresql/10/main/pg_hba.conf /var/lib/postgresql/10/main/.'"
            copy_cmd2 = "lxc exec maas-snap-1 -- sh -c 'sudo cp /etc/postgresql/10/main/pg_ident.conf /var/lib/postgresql/10/main/.'"
            chown_cmd = "lxc exec maas-snap-1 -- sh -c 'sudo chown postgres:postgres /var/lib/postgresql/10/main/pg_hba.conf'"
            chown_cmd2 = "lxc exec maas-snap-1 -- sh -c 'sudo chown postgres:postgres /var/lib/postgresql/10/main/pg_ident.conf'"
            install_cmd = "lxc exec maas-snap-1 -- sh -c 'install -o postgres -g postgres -m 0700 -d /var/lib/postgresql/10/main/tmp'"
            run(copy_cmd)
            run(chown_cmd)
            run(copy_cmd2)
            run(chown_cmd2)
            run(install_cmd)
            run('lxc exec maas-snap-1 sudo systemctl restart postgresql')
            sync_postgres_slaves()
        # configure service to start manually
       
        manual_cmd="lxc exec maas-snap-%s -- sh -c 'echo manual |sudo tee /etc/postgresql/10/main/start.conf'"  % (i)
        run(manual_cmd)
        stop_cmd="lxc exec maas-snap-%s -- sh -c 'sudo systemctl daemon-reload && sudo systemctl stop postgresql'"  % (i)
        daemon_cmd="lxc exec maas-snap-%s -- sh -c 'sudo systemctl disable postgresql && sudo systemctl disable postgresql@10-main'"  % (i)
        run(stop_cmd)
        run(daemon_cmd)
        configure_corosync()
    configure_postgres_pacemaker()
    sleep(65)
    sync_slaves_if_not()

def sync_postgres_slaves(vip=None):
    master_ip=get_container_ip('maas-snap-1')
    if vip:
        gateway = get_lxd_bridge_gateway('lxdbr0')
        subnet_ls = gateway.split('.')
        subnet_ls[3] = '253'
        vip_addr = '.'.join(subnet_ls)
        master_ip=vip_addr        
    stop_cmd1 = "lxc exec maas-snap-2 -- sh -c 'sudo systemctl stop postgresql'"
    stop_cmd2 = "lxc exec maas-snap-3 -- sh -c 'sudo systemctl stop postgresql'"
    delete_cmd1 = "lxc exec maas-snap-2 -- sh -c 'sudo rm -rf /var/lib/postgresql/10/main/*'"
    delete_cmd2 = "lxc exec maas-snap-3 -- sh -c 'sudo rm -rf /var/lib/postgresql/10/main/*'"
    sync_cmd1 = "lxc exec maas-snap-2 -- sh -c 'sudo -u postgres pg_basebackup -h %s -D /var/lib/postgresql/10/main -v --wal-method=stream'" % (master_ip)
    sync_cmd2 = "lxc exec maas-snap-3 -- sh -c 'sudo -u postgres pg_basebackup -h %s -D /var/lib/postgresql/10/main -v --wal-method=stream'" % (master_ip)
    run(stop_cmd1)
    run(stop_cmd2)
    run(delete_cmd1)
    run(delete_cmd2)
    run(sync_cmd1, output=False)
    sleep(45)
    run(sync_cmd2, output=False)
    

def configure_postgres_pacemaker():
    gateway = get_lxd_bridge_gateway('lxdbr0')
    cidr = get_lxd_bridge_subnet('lxdbr0')
    subnet_ls = gateway.split('.')
    subnet_ls[3] = '253'
    vip_addr = '.'.join(subnet_ls)        
    script_template = '''#!/bin/bash
sed -i 's/\\^node/node/g' /usr/lib/ocf/resource.d/heartbeat/pgsql

crm options pager cat
crm configure property cluster-recheck-interval=10s
crm configure property stonith-enabled="false"
crm configure rsc_defaults resource-stickiness=INFINITY
crm configure rsc_defaults migration-threshold=10

crm configure primitive pgsql ocf:heartbeat:pgsql \
  params rep_mode="sync" \
    pgctl="/usr/lib/postgresql/10/bin/pg_ctl" \
    psql="/usr/bin/psql" \
    pgdata="/var/lib/postgresql/10/main/" \
    socketdir="/var/run/postgresql" \
    config="/etc/postgresql/10/main/postgresql.conf" logfile="/var/log/postgresql/postgresql-10-ha.log" \
    master_ip="%s" \
    node_list="maas-snap-1 maas-snap-2 maas-snap-3" \
    primary_conninfo_opt="keepalives_idle=60 \
    keepalives_interval=5 \
    keepalives_count=5" \
    restart_on_promote="true" \
    op start timeout="60s" interval="0s" on-fail="restart" \
    op monitor timeout="60s" interval="4s" on-fail="restart" \
    op monitor timeout="60s" interval="3s" on-fail="restart" \
    role="Master" \
    op promote timeout="60s" interval="0s" on-fail="restart" \
    op demote  timeout="60s" interval="0s" on-fail="stop" \
    op stop timeout="60s" interval="0s" on-fail="block" \
    op notify timeout="60s" interval="0s" 


crm configure ms ms_pgsql pgsql meta master-max="1" \
    master-node-max="1" clone-max="3" clone-node-max="1" \
    notify="true"

crm configure primitive res_pgsql_vip ocf:heartbeat:IPaddr2 \
    params ip=%s cidr_netmask=%s op monitor interval=30s meta \
    migration-threshold=0
crm configure colocation pgsql_vip inf: res_pgsql_vip \
                ms_pgsql:Master

crm configure order ord_promote 0: ms_pgsql:promote \
                res_pgsql_vip:start symmetrical=false

crm configure order ord_demote inf: ms_pgsql:demote \
                res_pgsql_vip:stop symmetrical=false

crm resource cleanup pgsql''' % (vip_addr, vip_addr, cidr)
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(script_template)
    lxd_push_command = 'lxc file push %s maas-snap-1/home/ubuntu/pacemaker.sh' % (tmp_file.name)
    lxd_chmod_command = "lxc exec maas-snap-1 -- sh -c 'sudo chmod +x /home/ubuntu/pacemaker.sh'"
    lxd_exec_command = "lxc exec maas-snap-1 -- sh -c 'sudo sh /home/ubuntu/pacemaker.sh'"
    run(lxd_push_command)
    run(lxd_chmod_command)
    try:
        run(lxd_exec_command)
    except:
        pass    

def sync_slaves_if_not():
    gateway = get_lxd_bridge_gateway('lxdbr0')
    subnet_ls = gateway.split('.')
    subnet_ls[3] = '253'
    vip_addr = '.'.join(subnet_ls)   

    cmd1 = "lxc exec maas-snap-1 -- sh -c 'sudo crm status|grep unknown|grep maas-snap-2'"
    cmd2 = "lxc exec maas-snap-1 -- sh -c 'sudo crm status|grep unknown|grep maas-snap-3'"
    output1 = run(cmd1) 
    if output1:
        cmd_sync = "lxc exec maas-snap-2 -- sh -c 'sudo rm -rf /var/lib/postgresql/10/main/* && sudo -u postgres pg_basebackup -h %s -D /var/lib/postgresql/10/main -v --wal-method=stream'" % vip_addr
        run(cmd_sync)
        run('lxc exec maas-snap-2 sudo crm resource cleanup pgsql')
        sleep(10)
    output2 = run(cmd2) 
    if output2:
        cmd_sync = "lxc exec maas-snap-3 -- sh -c 'sudo rm -rf /var/lib/postgresql/10/main/* && sudo -u postgres pg_basebackup -h %s -D /var/lib/postgresql/10/main -v --wal-method=stream'" % vip_addr
        run(cmd_sync)
        run('lxc exec maas-snap-3 sudo crm resource cleanup pgsql')

def configure_corosync():
    corosync_tempate = '''#####
totem {
	version: 2
	token: 3000
	token_retransmits_before_loss_const: 10
	join: 60
	consensus: 3600
	vsftype: none
	max_messages: 20
	clear_node_high_bit: yes
	secauth: off
	threads: 0
	ip_version: ipv4
	rrp_mode: none
	transport: udpu
}
nodelist {
	node {
		ring0_addr: %s
		nodeid: 1
        name: maas-snap-1
	}
	node {
		ring0_addr: %s
		nodeid: 2
        name: maas-snap-2
	}
	node {
		ring0_addr: %s
		nodeid: 3
        name: maas-snap-3
	}
}
quorum{
        provider: corosync_votequorum
        expected_votes: 3 
    }
logging {
	fileline: off
	to_stderr: yes
	to_logfile: no
	to_syslog: yes
	syslog_facility: daemon
	debug: off
	logger_subsys {
		subsys: QUORUM
		debug: off
	}
}''' % (get_container_ip('maas-snap-1'), get_container_ip('maas-snap-2'), get_container_ip('maas-snap-3'))    
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(corosync_tempate)
    for i in range(1,4):      
        lxd_push_command = 'lxc file push %s maas-snap-%s/home/ubuntu/corosync.conf' % (tmp_file.name, i)
        lxd_cp_command = 'lxc exec maas-snap-%s sudo cp /home/ubuntu/corosync.conf /etc/corosync/corosync.conf' % (i)
        run(lxd_push_command)
        run(lxd_cp_command)
        run('lxc exec maas-snap-%s sudo systemctl restart corosync' % i)

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

def create_maas_admin(email, lp_id):
    cmd1 = 'lxc exec maas-snap-3 -- sh -c "maas createadmin --username admin --password password --email %s --ssh-import lp:%s"' % (email, lp_id)
    cmd2 = 'lxc exec maas-snap-3 -- sh -c "maas apikey --username admin |tee -a /home/ubuntu/api-key"'
    run(cmd1)
    run(cmd2)
def import_images_and_keys():
    container_three_ip = get_container_ip('maas-snap-3')
    maas_url = 'http://%s/MAAS' % container_three_ip
    api_key = run('lxc exec maas-snap-3 -- sh -c "maas apikey --username admin"')
    login_cmd = 'lxc exec maas-snap-3 -- sh -c "maas login admin %s %s"'  % (maas_url, api_key.decode())
    run(login_cmd)
    bionic_cmd = 'maas admin boot-source-selections create 1 os="ubuntu" release="bionic" arches="amd64" \
    subarches="*" labels="*"'
    focal_cmd = 'maas admin boot-source-selections create 2 \
    os="ubuntu" release="focal" arches="amd64" \
    subarches="*" labels="*"'
    import_cmd = 'maas admin boot-resources import'
    run('lxc exec maas-snap-3 -- sh -c "{}"'.format(bionic_cmd))
    run('lxc exec maas-snap-3 -- sh -c "{}"'.format(focal_cmd))
    run('lxc exec maas-snap-3 -- sh -c "{}"'.format(import_cmd))

def add_kvm_pod(username):
    #NOTE: don't run this until configuring DHCP
    #Probably should add as a disclaimer that doing so will result in all current VMS getting comissioned if anyone runs this
    gateway = get_lxd_bridge_gateway('lxdbr0')
    cmd = 'maas admin vm-hosts create type=virsh power_address=%s@%s/system' % (username,gateway)
    run('lxc exec maas-snap-3 -- sh -c "%s"' % cmd) 


def enable_dhcp_on_maas_network():
    pass

def configure_ssh_key(location):
    #NOTE: ask user for location of id_rsa at beginning
    for i in range(1,4):
        run('lxc exec maas-snap-%s -- sh -c "mkdir /var/snap/maas/current/root/.ssh"' %i )
        run('lxc file push %s maas-snap-%s/var/snap/maas/current/root/.ssh/id_rsa' % (location, i))
        run('lxc exec maas-snap-%s -- sh -c "chmod 400 /var/snap/maas/current/root/.ssh/id_rsa"' % i)

def configure_maas_vip():
    global MAAS_VIP
    gateway = get_lxd_bridge_gateway('lxdbr0')
    cidr = get_lxd_bridge_subnet('lxdbr0')
    subnet_ls = gateway.split('.')
    subnet_ls[3] = '252'
    vip_addr = '.'.join(subnet_ls) 
    MAAS_VIP = vip_addr
    template = '''####
#!/bin/bash
crm configure property stonith-enabled="false"
crm configure rsc_defaults resource-stickiness=INFINITY
crm configure rsc_defaults migration-threshold=10
crm configure primitive res_maas_vip ocf:heartbeat:IPaddr2 \
    params ip=%s cidr_netmask=%s op monitor interval=10s meta \
    migration-threshold=0 
crm configure primitive haproxy lsb:haproxy op monitor interval=15s''' % (vip_addr, cidr)
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(template)    
    lxd_push_command = 'lxc file push %s maas-snap-3/home/ubuntu/maas_reg_vip.sh' % (tmp_file.name)
    lxd_chmod_command = 'lxc exec maas-snap-3 chmod +x /home/ubuntu/maas_reg_vip.sh'
    lxd_create_command = 'lxc exec maas-snap-3 -- sh -c " sh /home/ubuntu/maas_reg_vip.sh"'
    run(lxd_push_command)
    run(lxd_chmod_command)
    run(lxd_create_command)
    ensure_haproxy_started()

def pg_sql_cleanup():
    for i in range(1,4):
        cmd = 'lxc exec maas-snap-%i -- sh -c "rm /var/lib/pgsql/tmp/PGSQL.lock"' % i
        run(cmd)
        run('lxc exec maas-snap-%i -- sh -c "crm_resource --cleanup"' % i)

def ensure_haproxy_started():
    for i in range(1,4):
        cmd1 = 'lxc exec maas-snap-%s -- sh -c "sudo systemctl stop haproxy"' % i
        cmd2 = 'lxc exec maas-snap-%s -- sh -c "sudo systemctl start haproxy"' % i
        run(cmd1)
        run(cmd2)        

def main():
    lp_id = input('Enter launchpad id: ' )
    email = input('Enter email: ')
    username = input('Enter your username (e.g. /home/$username): ')
    id_rsa_path = input('Enter path to private key, e.g. (/home/$username/.ssh/id_rsa) : ')
    configure_lxd(lp_id)
    create_containers()
    while True:
        if is_maas_installed() and is_postgres_installed() and is_haproxy_installed():
            break
        else:
            sleep(30)       
    generate_netplan('maas-snap-1')
    generate_netplan('maas-snap-2')
    generate_netplan('maas-snap-3')
    configure_hosts_file()
    sleep(90)
    configure_postgres()
    configure_haproxy()
    configure_maas_snaps()
    create_maas_admin(email, lp_id)
    configure_maas_vip()
    import_images_and_keys()
    configure_ssh_key(id_rsa_path)
    configure_kvm_host()
    configure_maas_network_on_containers()
    add_kvm_pod(username)
    pg_sql_cleanup()
    ensure_haproxy_started()
    print("Ready to go....")
    print("Access MaaS at http://%s" % MAAS_VIP)
    print("Username is 'admin' and password is 'password'")

main()