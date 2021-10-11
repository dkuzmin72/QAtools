#!/bin/python3 -u
import argparse
import datetime
import getpass
import glob
import os
import os.path
import pexpect
import random
import subprocess
import sys
import time
import yaml
import logging
import requests
import getpass

from configparser import ConfigParser
from copy import copy
from multiprocessing import Pool

UFMAPL_PATH = '/auto/UFM/UFMAPL*'
UFM_APL_NODES = ['master', 'slave', 'sm_only']
HA_WAIT = 20

class Remanufacture:
    def __init__(self, options):
        now = datetime.datetime.now()
        ymd = now.strftime("%Y%m%d")
        logging.basicConfig(filename='remanufacture_'+ymd+'.log', filemode='w', format="%(asctime)s [%(levelname)s]    %(message)s", level=logging.DEBUG)
        self.options = options
        self.remanufacture_done = False
        if not self.options['do_manufact']:
            print("Remanufacture is not required according to the configuration")
            logging.warning("Remanufacture is not required according to the configuration")
            self.remanufacture_done = True
        self.remanufacture_version = None

    def do_it_all(self):
        # Steps:
        # 1. Remanufacture
        #    initialization
        #    check that version was upgraded
        # 2. License install
        #    Check that license was installed properly
        # 3. Configuration of nodes
        #    HA at this stage? According to Kobi: "You should configure HA after the manufacture"
        # 4. In-service upgrade
        #    Do in-service upgrade or just upgrade
        #    Check that UFMAPL was upgraded successfully
        # 5. In-service upgrade or just upgrade
        #    Check that UFMAPL was upgraded successfully
        # 6. Set additional parameters (for example SHARP)
        logging.info('Started')
        print("Started...")

        for version in self.options['versions']:
            self.upgrade(version.strip())

        self.set_additinal_params()

        logging.info('Done')
        print("Finished")

    def upgrade(self, version):
        if not self.remanufacture_done:
            self.remanufacture_version = version
            self.remanufacture()
            self.remanufacture_done = True
        else:
            self.inservice_upgrade(version)

        if self.options['slave'] and version == self.options['ha_after']:
            self.configure_ha()

        self.check_ufm_status()
        self.check_ufm_log_files()

        self.check_ufm_rest_api()


    def remanufacture(self):
        logging.info("Remanufacure started on: " + self.options['master'] + ", " + self.options['slave'] + ", " + self.options['sm_only'])

        n = 0
        nodes = []
        for node in UFM_APL_NODES:
            if self.options[node]:
                nodes.append(self.options[node])
                n += 1
        with Pool(processes=n) as pool:
            result = pool.map(self.remanufacture_node, nodes)

        self.init_ufmapl()  # plus license install
        self.check_ufm_version(self.remanufacture_version)

    def inservice_upgrade(self, version):
        arguments = []
        n = 0
        for node in UFM_APL_NODES:
            if self.options[node]:
                arguments.append( (self.options[node], version) )
                n += 1
        with Pool(processes=n) as pool:
            result = pool.map(self.inservice_upgrade_node, arguments)

        # do NOT run this in parallel
        self.reload_node(self.options['slave'], version)
        self.reload_node(self.options['master'], version)
        self.reload_node(self.options['sm_only'], version)

        if self.options['slave']:
            self.do_takeover(self.options['master'])
        else:
            # start UFM on the Master if we have only one node
            cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"enable\\" \\"configure terminal\\" \\"ufm start\\" 2>/dev/null'
            out = execute(cmd)
            time.sleep(10)


    def configure_ha(self):
        self.check_sm(self.options['master'])
        self.configure_sm_only_node(self.options['sm_only'])
        self.configure_ha_master_node(self.options['master'])
        self.wait_for_ha_ok(self.options['master'])

        self.configure_ha_slave_node(self.options['slave'])

    def check_sm(self, node):
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"enable\\" \\"configure terminal\\" \\"ufm start\\" 2>/dev/null'
        out = execute(cmd)
        if 'UFM has started' in out:
            logging.debug("UFM has started")
        elif 'Please stop all other SM and start UFM' in out:
            logging.error("SM running on other node - please stop all other SM")
            sys.exit("SM running on other node - please stop all other SM before running this script")
        elif 'UFM is already running' in out:
            logging.warning("UFM is already running")
        else:
            logging.debug('Unexpected: ' + out)
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"enable\\" \\"configure terminal\\" \\"no ufm start\\" 2>/dev/null'
        out = execute(cmd)

    def check_ufm_log_files(self):
        master = self.options['master']
        # /opt/ufm/log/console.log: show ufm console log matching ERROR
        logging.info("Checking log files")

        try:
            logging.debug("Checking log files...")
            license = self.options['license']
            cmd = 'ssh admin@' + master
            apl = pexpect.spawn(cmd)
            apl.expect('Password: ')
            apl.sendline(self.options['admin_passwd'])
            apl.expect('> ')

            logging.debug("MASTER: Enabling")
            apl.sendline('enable')
            apl.expect('# ')

            logging.debug("MASTER: Configuring")
            apl.sendline('configure terminal')
            apl.expect('(config)')

            logging.debug("MASTER: getting console.log")
            apl.sendline('_shell')
            logging.debug("Expecting License")
            apl.expect('License')
            apl.sendline(license)
            logging.debug("Expecting #")
            apl.expect('# ')
            apl.sendline('grep ERROR /opt/ufm/files/log/console.log | grep -v WARNING')
            apl.expect('# ')
            out = apl.before.strip().decode('utf-8')
            if out:
                print('WARNING: found ERRORs in console.log - please check log file')
            logging.debug(out.replace('\r', ''))

            logging.info('Check log files: Done')
            apl.sendline('exit')

            logging.info("Checking console.log done ")

        except pexpect.EOF:
            logging.error("Checking console.log. Got EOF.")
        except pexpect.TIMEOUT:
            logging.error("Checking console.log. Got TIMEOUT")


    def check_ufm_rest_api(self):
        # curl  -X GET https://smg-ib-apl017-gen25/ufmRest/resources/links -u admin:admin -k 2>/dev/null | grep source_guid
        # check that output is not empty
        cmd = 'curl -X GET https://' + self.options['master'] + '/ufmRest/resources/links -u admin:' + self.options['admin_passwd'] + ' -k 2>/dev/null | grep source_guid'
        out = execute(cmd)
        if not out:
            logging.error("Could not get response for links")
            print("ERROR: Empty output on curl request")
#        print('CURL: ' + out)

        # curl  -X GET https://smg-ib-apl017-gen25/ufmRest/resources/ports -u admin:admin -k 2>/dev/null | grep node_description
        # check that output is not empty
        cmd = 'curl -X GET https://' + self.options['master'] + '/ufmRest/resources/ports -u admin:' + self.options['admin_passwd'] + ' -k 2>/dev/null | grep node_description'
        out = execute(cmd)
        if not out:
            logging.error("Could not get response for ports")
            print("ERROR: Empty output on curl request")
#        print('CURL: ' + out)

    def check_ufm_status(self):
        # wait 10 seconds to get more correct result
        time.sleep(10)
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + self.options['master'] + ' cli -h \\"show ufm status\\" 2>/dev/null'
        out = execute(cmd)
        print(out)
        logging.debug(out)
        slave_node = self.options['sm_only']
        if slave_node:
            cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + slave_node + ' cli -h \\"show ufm status\\" 2>/dev/null'
            out = execute(cmd)
            logging.debug(out)
            print(out)


    def remanufacture_node(self, apl_node):
        version = self.remanufacture_version
        if not apl_node or not version:
            logging.warning("Remanufacturing: node name was not provived - skipping")
            print("Remanufacturing: node name was not provived - skipping")
            return
        print("Remanufacturing node: " + apl_node + " to version " + version)
        logging.debug("Remanufacturing node: " + apl_node + " to version " + version)
        ufm_path,ufm_iso = get_ufmapl_manufacture_iso(version)
        if not ufm_path or not ufm_iso:
            return

        rnd = str(random.randint(10001, 99999))
        iso = ufm_path + '/' + ufm_iso
        original_cwd = os.getcwd()
        print('Image: ' + iso)
        logging.debug('Image: ' + iso)

        username = getpass.getuser()
        custom_folder = 'ufmapl_re/' + username + rnd

        pxe_server = '10.211.0.104'
        pxe_folder = '/auto/GLIT/PXE/tftpboot/' + custom_folder
        print("PXE_FOLDER: " + pxe_folder)
        logging.debug("PXE_FOLDER: " + pxe_folder)
        cmd = 'mkdir -p ' + pxe_folder
        execute(cmd)

        ip = get_ip_address(apl_node)
        print("IP: " + str(ip))
        logging.debug("IP: " + str(ip))

        gw = '10.209.24.1'
        mac = get_mac_address(apl_node)
        print("MAC address of " + apl_node + " : " + str(mac))
        logging.debug("MAC address of " + apl_node + " : " + str(mac))

        mount = '/mnt/iso_' + rnd
        cmd = 'sudo mkdir -p ' + mount
        execute(cmd)
        cmd = 'sudo umount ' + mount + ' 2>&1|tee'
        execute(cmd)
        cmd = 'sudo mount -o loop ' + iso + ' ' + mount
        execute(cmd)

        workdir = "/tmp/remove_" + getpass.getuser() + "_"+ rnd
        print("Workdir: " + workdir)
        logging.debug("Workdir: " + workdir)
        cmd = 'sudo mkdir -p ' + workdir
        execute(cmd)
        cmd = 'sudo cp ' + mount + '/isolinux/rootflop.img ' + workdir + '/'
        execute(cmd)
        os.chdir(workdir)
        cwd = os.getcwd()
        if cwd != workdir:
            print("Unexpected error: cwd was not changed")
            logging.error("Unexpected error: cwd was not changed")

        # Check APL version and use another approach for versions < 4.2.x.x
#        ver=`echo $apl | cut -c 1,3`
#        if [ $ver -lt 42 ]; then
#            MOUNT_TMP=/mnt/rootflop_temp_$$
#            sudo mkdir -p $MOUNT_TMP
#            sudo mount -o ro,loop rootflop.img $MOUNT_TMP
#            sudo cp -r $MOUNT_TMP/* .
#            sudo umount $MOUNT_TMP
#            sudo rm -rf $MOUNT_TMP
#        else
#            sudo cat rootflop.img |sudo cpio -idmv
#        fi
        cmd = 'sudo cat rootflop.img |sudo cpio -idmv'
        execute(cmd)

        cmd = 'sudo touch ' + workdir + '/ci_app.patch'
        execute(cmd)
        cmd = 'sudo chmod 777 ' + workdir + '/ci_app.patch'
        execute(cmd)

# This patch configures eth interface to be able to download linux.img instead of cdrom
        patch_file = workdir + '/ci_app.patch'
        patch = """
--- etc/init.d/rcS.d/S34automfg     2020-11-29 14:12:49.011568000 +0200
+++ etc/init.d/rcS.d/S34automfg     2020-11-29 14:12:12.473504000 +0200
index e47f9ba..c4c239a 100644
@@ -77,6 +77,10 @@
 # to be automatically manufactured when the iso was booted, and would
 # then reboot the system.
 
+ifconfig eth0 """ + ip + """ netmask 255.255.252.0 up
+route add default gw 10.209.24.1 eth0
+/usr/bin/wget -O /mnt/cdrom/image.img http://""" + pxe_server + "/" + custom_folder + """/image.img
+
 PATH=/usr/bin:/bin:/usr/sbin:/sbin
 export PATH
 
"""
        with open(patch_file, 'w') as file:
            file.write(patch)

        cmd = 'sudo patch -p0 < ' + patch_file
        execute(cmd)
        cmd = 'sudo touch ' + workdir + '/rootflop_updated.img'
        execute(cmd)
        cmd = 'sudo chmod 777 ' + workdir + '/rootflop_updated.img'
        execute(cmd)
        cmd = 'sudo find . 2>/dev/null | sudo cpio -o -c -R root:root > ' + workdir + '/rootflop_updated.img'
        execute(cmd)

        cmd = 'scp ' + mount + '/image.img ' + pxe_server + ':/' + pxe_folder+ '/'
        execute(cmd)
        cmd = 'scp ' + mount + '/isolinux/linux ' + pxe_server + ':/' + pxe_folder + '/'
        execute(cmd)
        cmd = 'scp ' + workdir + '/rootflop_updated.img ' + pxe_server + ':/' + pxe_folder + '/rootflop.img'
        execute(cmd)
        cmd = 'sudo umount ' + mount
        execute(cmd)

        # Return to the original working directory
        os.chdir(original_cwd)

        # pxelinux.cfg has constant location
        pxe_file = '/auto/GLIT/PXE/tftpboot/pxelinux.cfg/01-' + mac
        print('PXE config file: ' + pxe_file)
        logging.debug('PXE config file: ' + pxe_file)
        if os.path.isfile(pxe_file) and not os.access(pxe_file, os.W_OK):
            logging.warning("No write permissions to " + pxe_file + " Removing it")
            print("WARN: No write permissions to " + pxe_file + " Removing it")
            execute('sudo rm -rf ' + pxe_file)
            return

        text = """SERIAL 0 115200 0x3
DEFAULT linux
TIMEOUT 10
PROMPT 1
LABEL linux
    KERNEL """ + custom_folder + """/linux
    APPEND console=ttyS0,115200n8 console=tty0
    INITRD """ + custom_folder + """/rootflop.img
"""
        with open(pxe_file, 'w') as file:
            file.write(text)

        reboot(apl_node)
        time.sleep(700)
        wait_for_ufmapl(apl_node)

        print("Removing files from " + pxe_folder + " and from " + workdir)
        logging.debug("Removing files from " + pxe_folder + " and from " + workdir)
        os.remove(pxe_file)
        execute('rm -rf ' + pxe_folder)
        execute('sudo rm -rf ' + workdir)

        print("Rebooting " + apl_node + " after Manufacture is done")
        logging.debug("Rebooting " + apl_node + " after Manufacture is done")
        reboot(apl_node)

        wait_for_ufmapl(apl_node)

        logging.info("Remanufactured " + apl_node + " to version " + version)


    def init_ufmapl_node(self, args):
        apl_node = args[0]
        apl_bond = args[1]
        if not apl_node:
            print("Init UFMAPL: node name was not provided - skipping")
            logging.warning("Init UFMAPL: node name was not provided - skipping")
            return
        print("Inititializing UFM Appliance on node " + apl_node)
        logging.debug("Inititializing UFM Appliance on node " + apl_node)
        passwd = self.options['admin_passwd']
        monitor_passwd = self.options['monitor_passwd']
        try:
            cmd = 'ssh admin@' + apl_node
            logging.debug("Executing: " + cmd)
            apl = pexpect.spawn(cmd)
            apl.expect('Password: ')
            logging.debug("Sending passwd: " + passwd)
            apl.sendline(passwd)
            logging.debug("Expecting configuration?")
            apl.expect('configuration? ')

            # Do you want to use the wizard for initial configuration?
            apl.sendline('yes')
            # Step 1: Hostname? [smg-ib-aplXXX-gen2]
            logging.debug("Expecting Hostname")
            apl.expect('Hostname')
            apl.sendline('')
            # Step 2: Use DHCP on eth0 interface? [yes]
            logging.debug("Expecting DHCP")
            apl.expect('DHCP')
            apl.sendline('')
            # Step 3: Enable IPv6? [yes]
            logging.debug("Expecting IPv6")
            apl.expect('IPv6')
            apl.sendline('')
            # Step 4: Enable IPv6 autoconfig (SLAAC) on eth0 interface? [no]
            logging.debug("Expecting SLAAC")
            apl.expect('SLAAC')
            apl.sendline('')
            # Step 5: Enable DHCPv6 on eth0 interface? [yes]
            logging.debug("Expecting DHCPv6")
            apl.expect('DHCPv6')
            apl.sendline('')

            # Step 6: Admin password (Must be typed)?
            logging.debug("Expecting Admin")
            apl.expect('Admin')
            apl.sendline(passwd)
            # Step 6: Confirm admin password?
            logging.debug("Expecting Confirm")
            apl.expect('Confirm')
            apl.sendline(passwd)
            # Step 7: Monitor password (Must be typed)?
            logging.debug("Expecting Monitor")
            apl.expect('Monitor')
            apl.sendline(monitor_passwd) # should be passwd_monitor
            # Step 7: Confirm monitor password?
            logging.debug("Expecting Confirm")
            apl.expect('Confirm')
            apl.sendline(passwd)

            # Step 8: bond0 IPv4 address and masklen? [0.0.0.0/0]
            logging.debug("Expecting bond0")
            apl.expect('bond0')
            apl.sendline(apl_bond)

            # Choice
            logging.debug("Expecting Choice")
            apl.expect('Choice')
            apl.sendline('')

            apl.sendline('exit')

            logging.info("Initialized UFM Appliance on node " + apl_node)

        except pexpect.EOF:
            print("Initializing UFM Appliance. Got EOF")
            logging.error("Initializing UFM Appliance. Got EOF")
        except pexpect.TIMEOUT:
            print("Initializing UFM Appliance. Got TIMEOUT")
            logging.error("Initializing UFM Appliance. Got TIMEOUT")

    def init_ufmapl(self):
        arguments = []
        n = 0
        for node in UFM_APL_NODES:
            if self.options[node]:
                arguments.append( (self.options[node], self.options[node + '_bond']) )
                n += 1
        with Pool(processes=n) as pool:
            result = pool.map(self.init_ufmapl_node, arguments)

        self.license_install() # plus license check

        # Start UFM on Master node only
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + self.options['master'] + ' cli -h \\"enable\\" \\"configure terminal\\" \\"ufm start\\" 2>/dev/null'
        out = execute(cmd)
        time.sleep(10)


    def check_apl_version(self, args):
        apl_node = args[0]
        version  = args[1]
        print_message = args[2]
        if not apl_node or not version:
            print("Checking Appliance version: node name was not provided - skipping")
            logging.warning("Checking Appliance version: node name was not provided - skipping")
            return
        if print_message:
            print("Checking Appliance version on node " + apl_node)
#        logging.info("Checking Appliance version on node " + apl_node)
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + apl_node + ' cli -h \\"show version\\" 2>/dev/null | grep "Product release"'
        # Output format: UFMAPL_4.6.0.20210413_UFM_6.6.99.15
        sss = execute(cmd)
        ver = sss.strip().split('_')
        if len(ver) > 1:
            ver = ver[1]
            if ver in version:
                if print_message:
                    print("\tVersion is correct:", apl_node, " Got: ", ver)
                    logging.info("Veirified UFMAPL version on node " + apl_node + " is correct: " + ver)
                return True
        if print_message:
            print("Incorrect version on :" + apl_node + " Expected: " + version + " But got: " + sss)
            logging.error("Incorrect version on :" + apl_node + " Expected: " + version +" But got: " + sss)
        return False

    def check_ufm_version(self, version):
        if not version:
            return
        arguments = []
        n = 0
        for node in UFM_APL_NODES:
            if self.options[node]:
                arguments.append( (self.options[node], version, True) )
                n += 1
        with Pool(processes=n) as pool:
            result = pool.map(self.check_apl_version, arguments)

    def check_license_on_node(self, node):
        if not node:
            print("Check license: node name was not provided - skipping")
            logging.warning("Check license: node name was not provided - skipping")
            return
        print("Checking License on node: " + node)
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"show ufm status\\" 2>/dev/null | grep license'
        out = execute(cmd)
        if "No valid license" in out:
            print("ERROR: License was not installed properly on: " + node)
            logging.error("ERROR: License was not installed properly on: " + node)
        else:
            print("License installed properly on: " + node)
            logging.info("License installed properly on: " + node)

    def license_install_on_node(self, node):
        if not node:
            print("License install: node name was not provided - skipping")
            return
        print("Installing License on node: " + node)
        logging.debug("Installing License on node: " + node)
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"enable\\" \\"configure terminal\\" \\"ufm license install scp://root:3tango@10.209.27.114:/.autodirect/mtrswgwork/refato/lic/volt-ufm-license_evaluation_adv_good_date.lic\\" 2>/dev/null'
        execute(cmd)

        self.check_license_on_node(node)


    def license_install(self):
        nodes = []
        n = 0
        for node in UFM_APL_NODES:
            if self.options[node]:
                nodes.append(self.options[node])
                n += 1
        with Pool(processes=n) as pool:
            result = pool.map(self.license_install_on_node, nodes)

    def configure_sm_only_node(self, node):
        if not node:
            print("SM only node was not provided - skipping")
            logging.warning("SM only node was not provided - skipping")
            return
        print("SM ONLY: Configuring " + node)
        logging.debug("SM ONLY: Configuring " + node)
        try:
            cmd = 'ssh admin@' + node
            apl = pexpect.spawn(cmd)
            apl.expect('Password: ')
            apl.sendline(self.options['admin_passwd'])
            apl.expect('> ')

            logging.debug("SMONLY: Enabling")
            apl.sendline('enable')
            apl.expect('#')

            logging.debug("SMONLY: Configuring")
            apl.sendline('configure terminal')
            apl.expect('(config)')

            apl.sendline('no ufm start')
            apl.expect('(config)')

            apl.sendline('ufm mode sm-only')
            apl.expect('(config)')

            apl.sendline('ufm start')
            apl.expect('(config)')

#            apl.sendline('no ufm start')
#            apl.expect('(config)')

            apl.sendline('configuration write')
            apl.expect('(config)')

            logging.debug("SMONLY: Exiting")
            apl.sendline('exit')
            apl.sendline('exit')

            logging.info("SM ONLY node " + node + "  configured")

        except pexpect.EOF:
            print("SM ONLY: Configuring - Got EOF.")
            logging.error("SM ONLY: Configuring - Got EOF.")
        except pexpect.TIMEOUT:
            print("SM ONLY: Configuring - Got TIMEOUT")
            logging.error("SM ONLY: Configuring - Got TIMEOUT")


    def configure_ha_master_node(self, master):
        if not master:
            print("Configuring HA - node name was not provided - skipping")
            logging.warning("Configuring HA - node name was not provided - skipping")
            return
        print("Configuring HA on node " + master)
        logging.debug("Configuring HA on node " + master)
        try:
            logging.debug("MASTER: Entering the node")
            cmd = 'ssh admin@' + master
            apl = pexpect.spawn(cmd)
            apl.expect('Password: ')
            apl.sendline(self.options['admin_passwd'])
            apl.expect('> ')

            logging.debug("MASTER: Enabling")
            apl.sendline('enable')
            apl.expect('# ')

            logging.debug("MASTER: Configuring")
            apl.sendline('configure terminal')
            apl.expect('(config)')

            logging.debug("MASTER: Stopping UFM")
            apl.sendline('no ufm start')
            apl.expect('(config)')

            logging.debug("MASTER: Setting routine engine")
            apl.sendline('ib sm routing-engines ftree')
            apl.expect('(config)')

            if self.options['root_guid1']:
                logging.debug("MASTER: Setting root_guid")
                guid = f"0x{self.options['root_guid1']:016x}"
                apl.sendline('ib sm root-guid ' + guid)
                apl.expect('(config)')

            if self.options['root_guid2']:
                logging.debug("MASTER: Setting root_guid")
                guid = f"0x{self.options['root_guid2']:016x}"
                apl.sendline('ib sm root-guid ' + guid)
                apl.expect('(config)')

            logging.debug("MASTER: Enabling SHARP")
            apl.sendline('ib sharp enable')
            apl.expect('(config)')

            expect_msg = 'mgmt-ha-active'

            slave_node = self.options['slave']
            if slave_node:
                slave_ip = get_ip_address(slave_node)
                logging.debug("\tslave_ip " + slave_ip)
                virt_ip   = self.options['apl_master_virt_ip']
                logging.debug("\tvirt IP - " + virt_ip)

                logging.debug("MASTER: Enabling HA mode")
                cmd = 'ufm ha configure ' + slave_ip + ' ' + virt_ip
                logging.debug('    Sending command: ' + cmd)
                apl.sendline(cmd)
                apl.expect('Please enter admin password for peer machine:')
                logging.debug('    Sending admin password')
                apl.sendline(self.options['admin_passwd'])
                logging.debug("MASTER: Waiting for HA configuration")
                apl.expect('mgmt-ha-active', timeout=120)

                smonly = self.options['sm_only']
                if smonly:
                    smonly_ip = get_ip_address(smonly)

                    logging.debug('MASTER: Changing Allow SM mode')
                    apl.sendline('ufm mode mgmt-allow-sm')
                    apl.expect('mgmt-allow-sm-ha-active')

                    logging.debug('MASTER: Registering SM_ONLY IP ' + smonly_ip)
                    apl.sendline('ufm external-sm register ip ' + smonly_ip)
                    apl.expect('Please enter admin password for external SM machine:')
                    apl.sendline(self.options['admin_passwd'])
                    expect_msg = 'mgmt-allow-sm-ha-active'
                    apl.expect(expect_msg)
                else:
                    logging.debug("MASTER: SM ONLY node was not provided")
            else:
                logging.debug("MASTER: slave node was not provided. Not setting SM only either")

            logging.debug('MASTER: Starting UFM')
#           Starting of UFM by pexpect may lead to timeout because output can be different
#            apl.sendline('ufm start')
#            apl.expect(expect_msg)
            cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + master + ' cli -h \\"enable\\" \\"configure terminal\\" \\"ufm start\\" 2>/dev/null'
            out = execute(cmd)
            logging.debug("UFM start output: " + out)

            apl.sendline('configuration write')

            logging.debug('MASTER: Exiting')
            apl.sendline('exit')
            apl.sendline('exit')

            logging.info("HA mode configured on master node " + master)

        except pexpect.EOF:
            logging.error("Setting HA parameters on master. Got EOF.")
        except pexpect.TIMEOUT:
            logging.error("Setting HA parameters on master. Got TIMEOUT")

    def configure_ha_slave_node(self, slave_node):
        if not slave_node:
            print("Configuring slave HA : node name was not provided - skipping")
            logging.warning("Configuring slave HA : node name was not provided - skipping")
            return
        print("Configuring HA on slave node " + slave_node)
        logging.debug("Configuring HA on slave node " + slave_node)
        try:
            logging.debug("SLAVE: Entering the node")
            cmd = 'ssh admin@' + slave_node
            apl = pexpect.spawn(cmd)
            apl.expect('Password: ')
            apl.sendline(self.options['admin_passwd'])
            apl.expect('> ')

            logging.debug("SLAVE: Enabling")
            apl.sendline('enable')
            apl.expect('#')

            logging.debug("SLAVE: Configuring")
            apl.sendline('configure terminal')
            apl.expect('(config)')

            smonly = self.options['sm_only']
            if smonly:
                smonly_ip = get_ip_address(smonly)
                logging.debug("SLAVE: Setting trust")
                apl.sendline('ufm external-sm trust ip ' + smonly_ip)
                apl.expect('Please enter admin password for external SM machine:')
                apl.sendline(self.options['admin_passwd'])
                apl.expect('(config)')

            apl.sendline('configuration write')
            apl.expect('(config)')

            logging.debug("SLAVE: Exiting")
            apl.sendline('exit')
            apl.sendline('exit')

            logging.info("HA configured on slave node " + slave_node)

        except pexpect.EOF:
            logging.error("Setting HA parameters on slave. Got EOF")
        except pexpect.TIMEOUT:
            logging.error("Setting HA parameters on slave. Got TIMEOUT")

    def wait_for_ha_ok(self, node):
        # if we have "InfiniBand interface is down" it means that Degraded will be forever
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"show ufm status\\" 2>/dev/null | grep "InfiniBand interface is down" '
        out = execute(cmd)
        if len(out) > 0:
            print("MASTER: InfiniBand interface is down - will not be waiting for status OK")
            logging.warning("MASTER: InfiniBand interface is down - will not be waiting for status OK")
            return

        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"show ufm status\\" 2>/dev/null | grep "High Availability Status" '
        print("Waiting for HA status is OK ", end='')
        logging.debug("Waiting for HA status is OK - timeout 15 min")
        timeout = 15*60 # 15 minutes is more than enough
        timer = 0
        while out.lower() != "ok":
            out = execute(cmd)
            out = out.split()[3]
            time.sleep(HA_WAIT)
            timer += HA_WAIT
            print('.', end='')
            if timer > timeout:
                print("HA enabling exceeded timeout. Aborting")
                logging.error("HA enabling exceeded timeout. Aborting")
                sys.exit(-1)
#            print("Timer = " + str(timer))
        print("")
        print("High Availability Status: " + out)
        logging.info("High Availability Status: " + out)

    def do_takeover(self, master):
        if not master:
            print("Doing takover - skipping")
            logging.debug("Skip takover step - master node name is empty")
            return
        print("Doing takover on the node: " + master)
        logging.debug("Doing takover on the node: " + master)
        try:
            logging.debug("MASTER: Entering the node")
            cmd = 'ssh admin@' + master
            apl = pexpect.spawn(cmd)
            apl.expect('Password: ')
            apl.sendline(self.options['admin_passwd'])
            apl.expect('> ')

            logging.debug("MASTER: Enabling")
            apl.sendline('enable')
            apl.expect('# ')

            logging.debug("MASTER: Configuring")
            apl.sendline('configure terminal')
            apl.expect('(config)')

            apl.sendline('ufm ha takeover')
            apl.expect('mgmt-allow-sm-ha-active')

            apl.sendline('configuration write')

            logging.debug('MASTER: Exiting')
            apl.sendline('exit')
            apl.sendline('exit')

            logging.info("Takover done on the node: " + master)

        except pexpect.EOF:
            logging.error("Doing takeover on master. Got EOF.")
        except pexpect.TIMEOUT:
            logging.error("Doing takeover on master. Got TIMEOUT")

    def inservice_upgrade_node(self, args):
        node = args[0]
        version = args[1]
        if not node or not version:
            print("Inservice upgrade: node name was not provided - skipping")
            logging.debug("Inservice upgrade: node name was not provided - skipping")
            return
        if self.check_apl_version((node, version, False)):
            print("Inservice upgrade: version " + version + " is already installed on node " + node + ". Skipped.")
            logging.debug("Inservice upgrade: version " + version + " is already installed on node " + node + ". Skipped.")
            return

        print("Inservice upgrade of " + node + " to version " + version)
        logging.debug("Inservice upgrade of " + node + " to version " + version)
        image_path,image_name = get_ufmapl_image(version)
        if not image_path or not image_name:
            return
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"enable\\" \\"configure terminal\\" \\"image fetch scp://dkuzmin:dkuzmin11@r-hpc-hn01' + image_path + '/' + image_name + '\\"  \\"image install ' + image_name + '\\"  \\"image boot next\\"  \\"configuration write\\"  2>/dev/null'
        execute(cmd)

    def reload_node(self, node, version):
        if not node:
            return
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"enable\\" \\"configure terminal\\"  \\"reload\\" 2>/dev/null'
        execute(cmd)
        time.sleep(120) # rebooting is not so fast

        wait_for_ufmapl(node)
        logging.info("Inservice upgrade finished on node: " + node)

        time.sleep(2) # wait couple seconds to wake up
        self.check_apl_version((node, version, True))


    def set_additinal_params(self):
        pass


def wait_for_server(node):
    if not node:
        return
    logging.debug("Waiting for " + node + " is back online...    ")
    cmd = 'ping -c 1 -w 10 ' + node + ' &>/dev/null'
    timer = 0
    timeout = 15 * 60
    while os.system(cmd):
        time.sleep(10)
        timer += HA_WAIT
        if timer > timeout:
            print("Wait for Server timeout. Timer: " + str(timer) + " Timeout: " + str(timeout))
            logging.error("Wait for Server timeout")
            return
    logging.debug(node + " is available")

def wait_for_ufmapl(ufmapl):
    if not ufmapl:
        return
    time.sleep(10) # it may take time to restart
    wait_for_server(ufmapl)
    time.sleep(10) # ufmapl may appear for a second and restart after that
    wait_for_server(ufmapl)

def get_ufmapl_manufacture_iso(version):
    ufm_path = UFMAPL_PATH + version + '_*/*' + version + '*.iso'
    files = glob.glob(ufm_path)
    if len(files) == 0:
        print("Could not find iso file for UFM Appliance version " + version)
#        logging.error("Could not find iso file for UFM Appliance version " + version)
        return(None, None)
    if len(files) == 1:
        path,delim,name = files[0].rpartition('/')
#        logging.debug(" Found iso: " + path + "/" + name)
        return (path, name)
    else:
        print("Found too many iso files suitable for this version: "+ version)
#        logging.error("Found too many iso files suitable for this version: "+ version)
        return(None, None)

def get_ufmapl_image(version):
    ufm_path = UFMAPL_PATH + version + '_*/*' + version + '*.img'
    files = glob.glob(ufm_path)
    if len(files) == 0:
        print("Could not find image file for UFM Appliance version " + version)
#        logging.error("Could not find iso file for UFM Appliance version " + version)
        return(None, None)
    if len(files) == 1:
        path,delim,name = files[0].rpartition('/')
#        logging.debug(" Found image: " + path + "/" + name)
        return (path, name)
    else:
        print("Found too many image files suitable for this version: " + version)
#        logging.error("Found too many image files suitable for this version: "+ version)
        return(None, None)

def check_version_exist(version):
    path,name = get_ufmapl_image(version)
    if not path or not name:
        sys.exit("ERROR: Please check your list of versions")

    path,name = get_ufmapl_manufacture_iso(version)
    if not path or not name:
        sys.exit("ERROR: Please check your list of versions")

def reboot(apl_node):
    if not apl_node:
        return
    cmd = 'ipmitool -I lanplus -H  ' + apl_node + '-ilo  -U admin -P admin power reset 2>/dev/null'
    execute(cmd)


# OUTDATED: I have this dictionary to keep only needed keys
ddddict_keys ={
    'do_manufact'  : False,
    'master'   : None,
    'apl_master_virt_ip' : None,
    'slave'    : None,
    'sm_only'  : None,
    'master_bond'  : None,
    'slave_bond'   : None,
    'sm_only_bond' : None,
    'root_guid1'   : 0,
    'root_guid2'   : 0,
    'ha_after'     : None,
    'versions'     : [],
    'admin_passwd' : None,
    'monitor_passwd' : None
}


class INI:
    # Class which reads configuration file
    # Can create a list of Jobs
    def __init__(self, config_file):
        self.tasks = []
        self.config_file = config_file
        self.options = {}


    def get_options(self):
        return self.options

    def read_config(self):

        if not self.config_file:
            print("Error: config file name is empty")
            logging.error("Error: config file name is empty")
            return

#        self.options = copy(dict_keys)

        config = ConfigParser()
        config.read(self.config_file)

        sections = config.sections()
        if 'UFMAPL' in sections:
            self.options['do_manufact']    = config.getboolean('UFMAPL', 'do_manufact', fallback = False)
            self.options['versions']       = []
            vers = config.get('UFMAPL', 'versions', fallback = [])
            if vers:
                self.options['versions']   = vers.split(',')
            self.options['ha_after']       = config.get('UFMAPL', 'ha_after', fallback = None)

        self.options['master'] = ''
        if 'APL_MASTER' in sections:
            self.options['master']     = config.get('APL_MASTER', 'name', fallback = '')
            self.options['master_bond']    = config.get('APL_MASTER', 'bond', fallback = None)

            self.options['apl_master_virt_ip']    = config.get('APL_MASTER', 'virt_ip', fallback = None)
            self.options['license']        = config.get('APL_MASTER', 'lic', fallback = None)

        self.options['slave'] = ''
        if 'APL_SLAVE' in sections:
            self.options['slave']      = config.get('APL_SLAVE', 'name', fallback = '')
            self.options['slave_bond']     = config.get('APL_SLAVE', 'bond' , fallback = None)

        self.options['sm_only'] = ''
        if 'APL_SM_ONLY' in sections:
            self.options['sm_only']    = config.get('APL_SM_ONLY', 'name' , fallback = '')
            self.options['sm_only_bond']   = config.get('APL_SM_ONLY', 'bond' , fallback = None)

        if 'PASSWD' in sections:
            self.options['admin_passwd']   = config.get('PASSWD', 'admin_passwd', fallback = '')
            self.options['monitor_passwd'] = config.get('PASSWD', 'monitor_passwd', fallback = '')

        if 'ROOT_GUIDS' in sections:
            guid    = config.get('ROOT_GUIDS', 'guid1', fallback = None)
            self.options['root_guid1'] = int(guid, 0) if guid else 0

            guid    = config.get('ROOT_GUIDS', 'guid2', fallback = None)
            self.options['root_guid2'] = int(guid, 0) if guid else 0

    def check_options(self):
        if 'admin_passwd' not  in self.options:
            sys.exit("admin password has to be set in ini file")
        else:
            if not self.options['admin_passwd']:
                sys.exit("admin password has to be set in ini file")

        if 'monitor_passwd' not  in self.options:
            sys.exit("monitor password has to be set in ini file")
        else:
            if not self.options['monitor_passwd']:
                sys.exit("monitor password has to be set in ini file")

        for version in self.options['versions']:
            check_version_exist(version.strip())


    def print_conf(self):
        for key in self.options.keys():
            if key in self.options:
                print(key + ' => ' + str(self.options[key]))



def execute(cmd):
    logging.debug("CMD: " + cmd)
    out = ""
    exe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out = exe.stdout.read().strip().decode('utf-8')
    return out

def get_ip_address(node):
    cmd= "nslookup " + node + " |grep Address|grep 10|tail -n1|awk '{print $NF}' 2>/dev/null"
    ip = execute(cmd)
    return ip

def get_mac_address(node):
    ip  = get_ip_address(node)
    cmd = "cat /.autodirect/LIT/SCRIPTS/DHCPD/list| grep " + node + " |grep " + ip + "|awk '{print $2}' | cut -d';' -f1|sed 's/:/-/g' 2>/dev/null"
    mac = execute(cmd)
    return mac


# TODO
# check that everthing is good after upgrade
# ask Refat about REST API command to check GUI workability
# curl  -X GET https://smg-ib-apl017-gen25/ufmRest/resources/links -u admin:admin -k 2>/dev/null | grep source_guid
# check that output is not empty
# curl  -X GET https://smg-ib-apl017-gen25/ufmRest/resources/ports -u admin:admin -k 2>/dev/null | grep node_description
# check that output is not empty

# show ufm console log matching ERROR  <-  /opt/ufm/log/console.log
#        remove WARNING
# show ufm event log matching ERROR    <- /opt/ufm/log/event.log
#    actually there are CRITICAL events...
# show log matching ERROR              <- /var/log/messages
#        remove [cli.NOTICE]

# Get more info how to do upgrade via IPv6 (Ariel)
if __name__ == "__main__":

    if getpass.getuser() == 'root':
        print("Do not run this script as 'root'")
        sys.exit(-1)

    python_version = int(sys.version[0])
    if python_version < 3:
        print("Error: This script requires Python version 3 and pexpect module installed")
        sys.exit(-1)

    args = argparse.ArgumentParser(description='A tool to remanufacture UFM Appliance machines')
    args.add_argument("-i", "--ini_file",     action='store',      help="Use this ini file", type = str)

    opts = args.parse_args()

    if not opts.ini_file:
        sys.exit('Error: No configuration file was provided. Please use either --ini_file _file_name_ or -i _file_name_')
    else:
        if not os.path.isfile(opts.ini_file):
            sys.exit('Error: could not find ini file: ' + opts.ini_file)

    # Information about what to run and how should be taken from configuration file
    cfg = INI(opts.ini_file)
    cfg.read_config()
#    cfg.print_conf()
    cfg.check_options()

    do = Remanufacture(cfg.get_options())
    do.do_it_all()
