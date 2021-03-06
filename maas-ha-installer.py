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
    configure_snappy_cmd = 'sudo snap install core18 && sudo snap install snapd'
    lxd_install_cmd = 'sudo snap install lxd --edge'
    juju_install_cmd = 'sudo snap install juju --classic --channel=latest/edge'
    if not is_lxd_installed():
        run(configure_snappy_cmd)
        run(lxd_install_cmd)
    if not is_juju_installed():
        run(juju_install_cmd)

def configure_lxd():
    # check if net up and if there is storage + profile
    if get_lxd_bridge_subnet('lxdbr0'):
        print("lxdbr0 already configured...skipping")
    else:
        run("lxc network create lxdbr0 bridge.mtu=9000 ipv4.address=10.32.125.1/22 ipv4.nat=true ipv6.address=none")
    storage_cmd = 'lxc storage ls|grep -v NAME|grep -v "+-----"'
    if run(storage_cmd):
        print("a storage pool is already configured....")
    else:
        run('sudo apt-get install zfsutils-linux -y')
        status=run("lxc storage create default zfs",output=False)    
        if int(status)==1:
            run("lxc storage create default dir ")
    profile_cmd = 'lxc profile list|grep maas|grep -v NAME|grep -v "+-----"'
    if run(profile_cmd):
        print("Profile already created....skipping")
    else:
        configure_lxd_profile()    

def get_user_lp_id():
    lp_id = input('Enter launchpad id: ')
    return lp_id

def configure_maas():
    gateway = get_lxd_bridge_gateway('lxdbr0')
    subnet_ls = gateway.split('.')
    subnet_ls[3] = '253'
    vip_addr = '.'.join(subnet_ls)
    region_template = '''###
database_host: %s
database_name: maasdb
database_pass: password
database_port: 5432
database_user: maas
''' % vip_addr           
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(region_template)
    for i in range(1,4):      
        lxd_push_command = 'lxc file push %s maas-snap-%s/home/ubuntu/regiond.conf' % (tmp_file.name, i)
        lxd_cp_command = 'lxc exec maas-snap-%s sudo cp /home/ubuntu/regiond.conf /etc/maas/regiond.conf' % (i)
        run(lxd_push_command)
        run(lxd_cp_command)
        run('lxc exec maas-snap-%s -- sh -c  "sudo apt-get install maas-region-controller maas-region-api maas-dns -y"' % i)
def configure_kvm_host():
    # run at the end, so it doesn't muck with get_ip function
    pass
# maas_network_template='''
# <network>
#   <name>maas</name>
#   <forward mode='nat'/>
#   <bridge name='virbr-maas' stp='on' delay='0'/>
#   <mac address='52:54:00:01:83:8a'/>
#   <ip address='192.168.122.1' netmask='255.255.255.0'>
#   </ip>
# </network>'''

def configure_maas_network_on_containers():
    pass

def configure_lxd_profile():
    profile_template = '''####
config:
  boot.autostart: "false" 
  user.user-data: |
    #cloud-config
    apt_sources:  
      - source: "ppa:maas/2.9"  
    packages:
      - openssh-server
      - corosync
      - pacemaker
      - crmsh
      - postgresql
      - maas-rack-controller
    ssh_import_id:
       - lp:gabriel1109    
    package_update: true
    package_upgrade: true

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
'''

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
        cmd = "lxc exec maas-snap-%s -- sh -c 'dpkg -l|grep maas-rack'" % (i)
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

def create_containers():
    cleanup = "lxc delete maas-snap-1 --force && lxc delete maas-snap-2 --force && lxc delete maas-snap-3 --force"
    cmd = "lxc launch ubuntu:focal maas-snap-1 -p maas && lxc launch ubuntu:focal maas-snap-2 -p maas  && lxc launch ubuntu:focal maas-snap-3 -p maas"
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

def generate_netplan(container_name):
    # wait at least a minute and a half while cloud-init does its dirty work
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

def configure_postgres():
    # disable systemd unit, confiugre postgres.conf, pga_hba.conf
    postgres_conf_template = '''###
listen_addresses = '*'
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'
log_timezone = 'Etc/UTC'
stats_temp_directory = '/var/run/postgresql/12-main.pg_stat_tmp'
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
#data_directory = '/var/lib/postgresql/12/main/'
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
    run('''lxc exec maas-snap-1 -- sh -c "pg_ctlcluster 12 main start"''')
    run('''lxc exec maas-snap-1 -- sh -c "sudo -u postgres psql -c \\"CREATE USER \\"maas\\" WITH ENCRYPTED PASSWORD 'password'\\""''')
    run("""lxc exec maas-snap-1 -- sh -c 'sudo -u postgres createdb -O "maas" "maasdb"'""")
    run('lxc exec maas-snap-1 -- sh -c "sudo systemctl restart postgresql"')    
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
        tmp_file.write(postgres_conf_template)

    for i in range(1,4):
        # configure postgres.conf
        lxd_push_command = 'lxc file push %s maas-snap-%s/home/ubuntu/postgresql.conf' % (tmp_file.name, i)
        lxd_cp_command = 'lxc exec maas-snap-%s sudo cp /home/ubuntu/postgresql.conf /etc/postgresql/12/main/postgresql.conf' % (i)
        run(lxd_push_command)
        run(lxd_cp_command)
        # configure pg_hba.conf
        replication_cmd="lxc exec maas-snap-%s -- sh -c 'echo host    replication    postgres     %s    trust |sudo tee -a /etc/postgresql/12/main/pg_hba.conf'"  \
        % (i, subnet_addr)
        access_cmd="lxc exec maas-snap-%s -- sh -c 'echo host    maasdb    maas     %s   md5 |sudo tee -a /etc/postgresql/12/main/pg_hba.conf'"  \
        % (i, subnet_addr)  
        run(replication_cmd)
        run(access_cmd)
    #    run("""lxc exec maas-snap-%s -- sh -c 'sed -i "s/\\^node/node/g" /usr/lib/ocf/resource.d/heartbeat/pgsql'""" % i)
        # configure pg stat
        run('''lxc exec maas-snap-%s -- sh -c \'echo "d /var/run/postgresql/12-main.pg_stat_tmp 2750 postgres postgres" > /etc/tmpfiles.d/12-main.pg_stat_tmp.conf\'''' % i)
        run("lxc exec maas-snap-%s -- sh -c 'systemd-tmpfiles --create'" % i)

        if i == 1:
            copy_cmd = "lxc exec maas-snap-1 -- sh -c 'sudo cp /etc/postgresql/12/main/pg_hba.conf /var/lib/postgresql/12/main/.'"
            copy_cmd2 = "lxc exec maas-snap-1 -- sh -c 'sudo cp /etc/postgresql/12/main/pg_ident.conf /var/lib/postgresql/12/main/.'"
            chown_cmd = "lxc exec maas-snap-1 -- sh -c 'sudo chown postgres:postgres /var/lib/postgresql/12/main/pg_hba.conf'"
            chown_cmd2 = "lxc exec maas-snap-1 -- sh -c 'sudo chown postgres:postgres /var/lib/postgresql/12/main/pg_ident.conf'"
            install_cmd = "lxc exec maas-snap-1 -- sh -c 'install -o postgres -g postgres -m 0700 -d /var/lib/postgresql/12/main/tmp'"
            run(copy_cmd)
            run(chown_cmd)
            run(copy_cmd2)
            run(chown_cmd2)
            run(install_cmd)
            run('lxc exec maas-snap-1 sudo systemctl restart postgresql')
            sync_postgres_slaves()
        # configure service to start manually
       
        manual_cmd="lxc exec maas-snap-%s -- sh -c 'echo manual |sudo tee /etc/postgresql/12/main/start.conf'"  % (i)
        run(manual_cmd)
#        stop_cmd="lxc exec maas-snap-%s -- sh -c 'sudo systemctl daemon-reload && sudo systemctl stop postgresql'"  % (i)
#        daemon_cmd="lxc exec maas-snap-%s -- sh -c 'sudo systemctl disable postgresql && sudo systemctl disable postgresql@12-main'"  % (i)
#        run(stop_cmd)
#        run(daemon_cmd)
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
    delete_cmd1 = "lxc exec maas-snap-2 -- sh -c 'sudo rm -rf /var/lib/postgresql/12/main/*'"
    delete_cmd2 = "lxc exec maas-snap-3 -- sh -c 'sudo rm -rf /var/lib/postgresql/12/main/*'"
    sync_cmd1 = "lxc exec maas-snap-2 -- sh -c 'sudo -u postgres pg_basebackup -h %s -D /var/lib/postgresql/12/main -v --wal-method=stream'" % (master_ip)
    sync_cmd2 = "lxc exec maas-snap-3 -- sh -c 'sudo -u postgres pg_basebackup -h %s -D /var/lib/postgresql/12/main -v --wal-method=stream'" % (master_ip)
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
crm options pager cat
crm configure property cluster-recheck-interval=10s
crm configure property stonith-enabled="false"
crm configure rsc_defaults resource-stickiness=INFINITY
crm configure rsc_defaults migration-threshold=10

crm configure primitive pgsql ocf:heartbeat:pgsql \
  params rep_mode="sync" \
    pgctl="/usr/lib/postgresql/12/bin/pg_ctl" \
    psql="/usr/bin/psql" \
    pgdata="/var/lib/postgresql/12/main/" \
    socketdir="/var/run/postgresql" \
    config="/etc/postgresql/12/main/postgresql.conf" logfile="/var/log/postgresql/postgresql-12-ha.log" \
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
    params ip=%s cidr_netmask=%s op monitor interval=10s meta \
    migration-threshold=0
crm configure colocation pgsql_vip inf: res_pgsql_vip \
                ms_pgsql:Master

crm configure order ord_promote Mandatory: ms_pgsql:promote \
                res_pgsql_vip:start symmetrical=false

crm configure order ord_demote Optional: ms_pgsql:demote \
                res_pgsql_vip:stop symmetrical=false

crm resource cleanup pgsql
crm resource prmote ms_pgql''' % (vip_addr, vip_addr, cidr)
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

    cmd1 = "lxc exec maas-snap-1 -- sh -c 'sudo crm status|grep -i stopped|grep maas-snap-2'"
    cmd2 = "lxc exec maas-snap-1 -- sh -c 'sudo crm status|grep -i stopped|grep maas-snap-3'"
    output1 = run(cmd1) 
    if output1:
        cmd_sync = "lxc exec maas-snap-2 -- sh -c 'sudo rm -rf /var/lib/postgresql/12/main/* && sudo -u postgres pg_basebackup -h %s -D /var/lib/postgresql/12/main -v --wal-method=stream'" % vip_addr
        run(cmd_sync)
        run('lxc exec maas-snap-2 sudo crm resource cleanup pgsql')
        sleep(10)
    output2 = run(cmd2) 
    if output2:
        cmd_sync = "lxc exec maas-snap-3 -- sh -c 'sudo rm -rf /var/lib/postgresql/12/main/* && sudo -u postgres pg_basebackup -h %s -D /var/lib/postgresql/12/main -v --wal-method=stream'" % vip_addr
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
quorum {
	provider: corosync_votequorum
	}
nodelist {
	node {
		ring0_addr: %s
		nodeid: 1
	}
	node {
		ring0_addr: %s
		nodeid: 2
	}
	node {
		ring0_addr: %s
		nodeid: 3
	}
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
        run('lxc exec maas-snap-%s -- sh -c "sudo systemctl restart corosync && sudo systemctl restart pacemaker"' % i)

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


configure_lxd()
create_containers()
while True:
    if is_maas_installed() and is_postgres_installed():
        break
    else:
        sleep(60)       
generate_netplan('maas-snap-1')
generate_netplan('maas-snap-2')
generate_netplan('maas-snap-3')
configure_hosts_file()
sleep(240)
configure_postgres()
configure_maas()
