#!/bin/python3 -u
import argparse
import getpass
import glob
import os.path
import pexpect
import random
import subprocess
import sys
import time
import yaml
import logging

from configparser import ConfigParser
from copy import copy
from multiprocessing import Pool

log = 0
dryrun = 0
UFMAPL_PATH = '/auto/UFM/UFMAPL*'

class Remanufacture:
    def __init__(self, options):
        logging.basicConfig(filename='remanufacture.log', filemode='w', format="%(asctime)s [%(levelname)s]    %(message)s", level=logging.DEBUG)
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
        logging.info('Start')
        print("Started remanufacture")

        for version in self.options['versions']:
            self.upgrade(version.strip())

        self.set_additinal_params()

        logging.info('Done')
        print("Remanufacture/upgrade finished")

    def upgrade(self, version):
        if not self.remanufacture_done:
            self.remanufacture_version = version
            self.remanufacture()
            self.remanufacture_done = True
        else:
            self.inservice_upgrade(version)

        if version == self.options['ha_after']:
            self.configure_ha()

        self.check_ufm_status()


    def check_ufm_status(self):
        # wait 10 seconds to get more correct result
        time.sleep(10)
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + self.options['apl_master'] + ' cli -h \\"show ufm status\\" 2>/dev/null'
        out = execute(cmd)
        print(out)
        logging.debug(out)
        slave_node = self.options['apl_sm_only']
        if slave_node and len(slave_node) != 0:
            cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + slave_node + ' cli -h \\"show ufm status\\" 2>/dev/null'
            out = execute(cmd)
            logging.debug(out)
            print(out)


    def remanufacture_node(self, apl_node):
        version = self.remanufacture_version
        if not apl_node or len(apl_node) == 0 or not version or len(version) == 0:
            logging.warning("Remanufacturing: node name was not provived - skipping")
            print("Remanufacturing: node name was not provived - skipping")
            return
        print("Remanufacturing node: " + apl_node + " to version " + version)
        logging.info("Remanufacturing node: " + apl_node + " to version " + version)
        ufm_path,ufm_iso = get_ufmapl_manufacture_iso(version)
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

        workdir = "/tmp/" + rnd
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
        logging.info("Rebooting " + apl_node + " after Manufacture is done")
        reboot(apl_node)

        wait_for_ufmapl(apl_node)

        logging.info("Remanufacturing node: " + apl_node + " to version " + version + " Done!")

    def remanufacture(self):
        nodes = []
        logging.info("Remanufacure started on: " + self.options['apl_master'] + ", " + self.options['apl_slave'] + ", " + self.options['apl_sm_only'])
        nodes.append(self.options['apl_master'])
        nodes.append(self.options['apl_slave'])
        nodes.append(self.options['apl_sm_only'])
        with Pool(processes=3) as pool:
            result = pool.map(self.remanufacture_node, nodes)

        self.init_ufmapl()  # plus license install
        self.check_ufm_version(self.remanufacture_version)


    def init_ufmapl_node(self, apl_node, apl_bond):
        if not apl_node or len(apl_node) == 0:
            print("Init UFMAPL: node name was not provided - skipping")
            logging.warning("Init UFMAPL: node name was not provided - skipping")
            return
        print("Inititializing UFM Appliance on node " + apl_node)
        logging.info("Inititializing UFM Appliance on node " + apl_node)
        passwd = self.options['admin_passwd']
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
            apl.sendline(passwd_monitor)
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

            logging.info("Inititializing UFM Appliance on node " + apl_node + " Done!")

        except pexpect.EOF:
            print("Initializing UFM Appliance. Got EOF")
            logging.error("Initializing UFM Appliance. Got EOF")
        except pexpect.TIMEOUT:
            print("Initializing UFM Appliance. Got TIMEOUT")
            logging.error("Initializing UFM Appliance. Got TIMEOUT")

    def init_ufmapl(self):
        self.init_ufmapl_node(self.options['apl_master'], self.options['master_bond'])
        self.init_ufmapl_node(self.options['apl_slave'], self.options['slave_bond'])
        self.init_ufmapl_node(self.options['apl_sm_only'], self.options['sm_only_bond'])

        self.license_install() # plus license check

    def check_apl_version(self, apl_node, version, print_message = True):
        if not apl_node or len(apl_node) == 0 or not version or len(version) == 0:
            print("Checking Appliance version: node name was not provided - skipping")
            logging.warning("Checking Appliance version: node name was not provided - skipping")
            return
        print("Checking Appliance version on node " + apl_node)
#        logging.info("Checking Appliance version on node " + apl_node)
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + apl_node + ' cli -h \\"show version\\" 2>/dev/null | grep "Product release"'
        # Output format: UFMAPL_4.6.0.20210413_UFM_6.6.99.15
        ver = execute(cmd)
        ver = ver.strip().split('_')
        if len(ver) > 1:
            ver = ver[1]
            if ver in version:
                if print_message:
                    print("\tVersion is correct:", apl_node, " Got: ", ver)
                    logging.info("Version on node " + apl_node + " is correct: " + ver)
                return True
        if print_message:
            print("Incorrect version on :", apl_node," Expected: ", version, " But got: ", ver)
            logging.error("Incorrect version on :", apl_node," Expected: ", version, " But got: ", ver)
        return False

    def check_ufm_version(self, version):
        if not version or len(version) == 0:
            return
        self.check_apl_version(self.options['apl_master'], version)
        self.check_apl_version(self.options['apl_slave'],  version)
        self.check_apl_version(self.options['apl_sm_only'], version)

    def license_install_on_node(self, node):
        if not node or len(node) == 0:
            print("License install: node name was not provided - skipping")
            return
        print("Installing License on node: " + node)
        logging.info("Installing License on node: " + node)
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"enable\\" \\"configure terminal\\" \\"ufm license install scp://root:3tango@10.209.27.114:/.autodirect/mtrswgwork/refato/lic/volt-ufm-license_evaluation_adv_good_date.lic\\" 2>/dev/null'
        execute(cmd)
#        logging.info("Installed license on node " + node)

    def check_license_on_node(self, node):
        if not node or len(node) == 0:
            print("Check license: node name was not provided - skipping")
            logging.warning("Check license: node name was not provided - skipping")
            return
        print("Checking License on node: " + node)
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"show ufm status\\" 2>/dev/null | grep license'
#        print("Executing: " + cmd)
#        out = os.popen(cmd).read().strip()
        out = execute(cmd)
        if "No valid license" in out:
            print("ERROR: License was not installed properly on: ", node)
            logging.error("ERROR: License was not installed properly on: ", node)
        else:
            print("License installed properly on: ", node)
            logging.info("License installed properly on: ", node)

    def license_install(self):
        self.license_install_on_node(self.options['apl_master'])
        self.license_install_on_node(self.options['apl_slave'])
        self.license_install_on_node(self.options['apl_sm_only'])

        self.check_license_on_node(self.options['apl_master'])
        self.check_license_on_node(self.options['apl_slave'])
        self.check_license_on_node(self.options['apl_sm_only'])

    def configure_sm_only_node(self, node):
        if not node or len(node) == 0:
            print("SM only node was not provided - skipping")
            logging.warning("SM only node was not provided - skipping")
            return
        print("SM ONLY: Configuring " + node)
        logging.info("SM ONLY: Configuring " + node)
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

            apl.sendline('no ufm start')
            apl.expect('(config)')

            apl.sendline('configuration write')
            apl.expect('(config)')

            logging.debug("SMONLY: Exiting")
            apl.sendline('exit')
            apl.sendline('exit')

            logging.info("SM ONLY: Configuring " + node + " Done!")

        except pexpect.EOF:
            print("SM ONLY: Configuring - Got EOF.")
            logging.error("SM ONLY: Configuring - Got EOF.")
        except pexpect.TIMEOUT:
            print("SM ONLY: Configuring - Got TIMEOUT")
            logging.error("SM ONLY: Configuring - Got TIMEOUT")


    def configure_ha_master_node(self, master):
        if not master or len(master) == 0:
            print("Configuring HA - node name was not provided - skipping")
            logging.warning("Configuring HA - node name was not provided - skipping")
            return
        print("Configuring HA on node " + master)
        logging.info("Configuring HA on node " + master)
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

            logging.debug("MASTER: Setting root_guid")
            guid = f"0x{self.options['root_guid1']:016x}"
            apl.sendline('ib sm root-guid ' + guid)
            apl.expect('(config)')

            logging.debug("MASTER: Setting root_guid")
            guid = f"0x{self.options['root_guid2']:016x}"
            apl.sendline('ib sm root-guid ' + guid)
            apl.expect('(config)')

            logging.debug("MASTER: Enabling SHARP")
            apl.sendline('ib sharp enable')
            apl.expect('(config)')

            slave_node = self.options['apl_slave']
            if slave_node and len(slave_node) > 0:
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

                sm_only = self.options['apl_sm_only']
                if sm_only and len(sm_only) > 0:
                    sm_only_ip = get_ip_address(sm_only)

                    logging.debug('MASTER: Changing Allow SM mode')
                    apl.sendline('ufm mode mgmt-allow-sm')
                    apl.expect('mgmt-allow-sm-ha-active')

                    logging.debug('MASTER: Registering SM_ONLY IP ' + sm_only_ip)
                    apl.sendline('ufm external-sm register ip ' + sm_only_ip)
                    apl.expect('Please enter admin password for external SM machine:')
                    apl.sendline(self.options['admin_passwd'])
                    apl.expect('mgmt-allow-sm-ha-active')
                else:
                    logging.debug("MASTER: SM ONLY node was not provided")
            else:
                logging.debug("MASTER: slave node was not provided. Not setting SM only either")

            logging.debug('MASTER: Starting UFM')
            apl.sendline('ufm start')
            apl.expect('mgmt-allow-sm-ha-active')

            apl.sendline('configuration write')

            logging.debug('MASTER: Exiting')
            apl.sendline('exit')
            apl.sendline('exit')

            logging.info("Configuring HA on node " + master + " Done!")

        except pexpect.EOF:
            logging.error("Setting HA parameters on master. Got EOF.")
        except pexpect.TIMEOUT:
            logging.error("Setting HA parameters on master. Got TIMEOUT")

    def configure_ha_slave_node(self, slave_node):
        if not slave_node or len(slave_node) == 0:
            print("Configuring slave HA : node name was not provided - skipping")
            logging.warning("Configuring slave HA : node name was not provided - skipping")
            return
        print("Configuring HA on slave node " + slave_node)
        logging.info("Configuring HA on slave node " + slave_node)
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

            sm_only = self.options['apl_sm_only']
            if sm_only and len(sm_only) > 0:
                sm_only_ip = get_ip_address(sm_only)
                logging.debug("SLAVE: Setting trust")
                apl.sendline('ufm external-sm trust ip ' + sm_only_ip)
                apl.expect('Please enter admin password for external SM machine:')
                apl.sendline(self.options['admin_passwd'])
                apl.expect('(config)')

            apl.sendline('configuration write')
            apl.expect('(config)')

            logging.debug("SLAVE: Exiting")
            apl.sendline('exit')
            apl.sendline('exit')

            logging.info("Configuring HA on slave node " + slave_node + " Done!")

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
        logging.info("Waiting for HA status is OK ")
# add timeout here
        while out.lower() != "ok":
            out = execute(cmd)
            out = out.split()[3]
            time.sleep(10)
            print('.', end='')
        print("")
        print("High Availability Status: " + out)
        logging.info("High Availability Status: " + out)

    def configure_ha(self):
        self.configure_sm_only_node(self.options['apl_sm_only'])
        self.configure_ha_master_node(self.options['apl_master'])
        self.wait_for_ha_ok(self.options['apl_master'])

        self.configure_ha_slave_node(self.options['apl_slave'])

    def do_takeover(self, master):
        if not master or len(master) == 0:
            print("Doing takover - skipping")
            logging.debug("Skip takover step - master node name is empty")
            return
        print("Doing takover on the node: " + master)
        logging.info("Doing takover on the node: " + master)
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

            logging.info("Doing takover on the node: " + master + " Done!")

        except pexpect.EOF:
            logging.error("Doing takeover on master. Got EOF.")
        except pexpect.TIMEOUT:
            logging.error("Doing takeover on master. Got TIMEOUT")

    def inservice_upgrade_node(self, node, version):
        if not node or len(node) == 0 or not version or len(version) == 0:
            print("Inservice upgrade: node name was not provided - skipping")
            logging.debug("Inservice upgrade: node name was not provided - skipping")
            return
        if self.check_apl_version(node, version, False):
            print("Inservice upgrade: version " + version + " is already installed on node " + node + ". Skipped.")
            logging.debug("Inservice upgrade: version " + version + " is already installed on node " + node + ". Skipped.")
            return

        print("Inservice upgrade on node: " + node)
        logging.info("Inservice upgrade on node: " + node)
        image_path,image_name = get_ufmapl_image(version)
        cmd = 'sshpass -p ' + self.options['admin_passwd'] + ' ssh admin@' + node + ' cli -h \\"enable\\" \\"configure terminal\\" \\"image fetch scp://dkuzmin:dkuzmin11@r-hpc-hn01' + image_path + '/' + image_name + '\\"  \\"image install ' + image_name + '\\"  \\"image boot next\\"  \\"configuration write\\"  \\"reload\\" 2>/dev/null'
        execute(cmd)
        time.sleep(120) # rebooting is not so fast

        wait_for_ufmapl(node)

        time.sleep(2) # wait couple seconds to wake up
        self.check_apl_version(node, version)


    def inservice_upgrade(self, version):
# think about run fetching in parallel
        self.inservice_upgrade_node(self.options['apl_slave'],  version)
        self.inservice_upgrade_node(self.options['apl_master'], version)
        self.inservice_upgrade_node(self.options['apl_sm_only'], version)

        self.do_takeover(self.options['apl_master'])

    def set_additinal_params(self):
        pass


def wait_for_server(node):
    logging.debug("Waiting for " + node + " is back online...    ")
    cmd = 'ping -c 1 -w 10 ' + node + ' &>/dev/null'
    while os.system(cmd):
        time.sleep(10)
    logging.debug(node + " is available")

def wait_for_ufmapl(ufmapl):
    time.sleep(10) # it may take time to restart
    wait_for_server(ufmapl)
    time.sleep(10) # ufmapl may appear for a second and restart after that
    wait_for_server(ufmapl)

def get_ufmapl_manufacture_iso(version):
    ufm_path = UFMAPL_PATH + version + '_*/*' + version + '*.iso'
    files = glob.glob(ufm_path)
    if len(files) == 0:
        print("Could not find iso file for UFM Appliance version " + version)
        logging.error("Could not find iso file for UFM Appliance version " + version)
        return(None, None)
    if len(files) == 1:
        path,delim,name = files[0].rpartition('/')
#        cmd = 'ls -l ' + files[0]
#        execute(cmd)
        logging.debug(" Found iso: " + path + "/" + name)
        return (path, name)
    else:
        print("Found too many iso files suitable for this version: "+ version)
        logging.error("Found too many iso files suitable for this version: "+ version)
        return(None, None)

def get_ufmapl_image(version):
    ufm_path = UFMAPL_PATH + version + '_*/*' + version + '*.img'
    files = glob.glob(ufm_path)
    if len(files) == 0:
        print("Could not find image file for UFM Appliance version " + version)
        logging.error("Could not find iso file for UFM Appliance version " + version)
        return(None, None)
    if len(files) == 1:
        path,delim,name = files[0].rpartition('/')
#        cmd = 'ls -l ' + files[0]
#        execute(cmd)
        logging.debug(" Found image: " + path + "/" + name)
        return (path, name)
    else:
        print("Found too many image files suitable for this version: " + version)
        logging.error("Found too many image files suitable for this version: "+ version)
        return(None, None)

def reboot(apl_node):
    cmd = 'ipmitool -I lanplus -H  ' + apl_node + '-ilo  -U admin -P admin power reset 2>/dev/null'
    execute(cmd)


# I have this dictionary to keep only needed keys
dict_keys ={
    'apl_master'   : None,
    'apl_master_virt_ip' : None,
    'apl_slave'    : None,
    'apl_sm_only'  : None,
    'master_bond'  : None,
    'slave_bond'   : None,
    'sm_only_bond' : None,
    'root_guid1'   : None,
    'root_guid2'   : None,
    'ufmapl_remanufacture_version' : None,
    'ha_after'                     : None,
    'ufmapl_update1_version'       : None,
    'ufmapl_update2_version'       : None,
    'ufmapl_update3_version'       : None,
    'versions'                      : None,
    'admin_passwd'           : None
}


class Config:
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

        def_values = copy(dict_keys)
        with open(self.config_file) as f:
                items = yaml.full_load(f)

                conf = items['options']
                for key in dict_keys.keys():
                    if key in conf:
                        self.options[key] = conf[key]

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

        self.options = copy(dict_keys)

        config = ConfigParser()
        config.read(self.config_file)

        self.options['do_manufact'] = config['UFMAPL'].getboolean('do_manufact')
        self.options['versions']    = config['UFMAPL']['versions'].split(',')
        self.options['ha_after']    = config['UFMAPL']['ha_after'].strip()

        self.options['apl_master']  = config['APL_MASTER']['name'].strip()
        self.options['apl_slave']   = config['APL_SLAVE']['name'].strip()
        self.options['apl_sm_only'] = config['APL_SM_ONLY']['name'].strip()

        self.options['apl_master_virt_ip'] = config['APL_MASTER']['virt_ip'].strip()

        self.options['master_bond']   = config['APL_MASTER']['bond'].strip()
        self.options['slave_bond']    = config['APL_SLAVE']['bond'].strip()
        self.options['sm_only_bond']  = config['APL_SM_ONLY']['bond'].strip()

        self.options['admin_passwd']  = config['PASSWD']['admin_passwd'].strip()

        self.options['root_guid1']   = int(config['ROOT_GUIDS']['guid1'].strip(), 0)
        self.options['root_guid2']   = int(config['ROOT_GUIDS']['guid2'].strip(), 0)

    def print_conf(self):
        for key in dict_keys.keys():
            if key in self.options:
                print(key + ' => ' + str(self.options[key]))


# can be removed?
def execute_system(cmd):
    logging.debug("Executing: " + cmd)
    # was os.system(cmd)
    out = ""
    exe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out = exe.stdout.read().strip().decode('utf-8')
    return out



def execute(cmd):
    logging.debug("Executing: " + cmd)
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

def dryrun():
    return dryrun

def set_dryrun(val):
    dryrun = val

def log():
    return log

def set_log(val):
    log = val


# TODO
# Add monitor passwd
# check that everthing is good after upgrade
# ask Refat about REST API command to check GUI workability
# check /var/log/console.log
# check /var/log/messages
# Get more info how to do upgrade via IPv6 (Ariel)
if __name__ == "__main__":

    python_version = int(sys.version[0])
    if python_version < 3:
        print("Error: This script requires Python version 3 and pexpect module installed")
        sys.exit(-1)

    args = argparse.ArgumentParser(description='A tool to remanufacture UFM Appliance machines')
    args.add_argument("-l", "--log",          action='store_true', help="Output internal information useful for debug purposes")
    args.add_argument("-d", "--dryrun",       action='store_true', help="Run scripts not starting real jobs")
    args.add_argument("-c", "--config_file",  action='store',      help="Use this config file (in yaml format)", type = str)
    args.add_argument("-i", "--ini_file",     action='store',      help="Use this ini file", type = str)

    opts = args.parse_args()
    set_log(opts.log)
    set_dryrun(opts.dryrun)

#    if log():
#        print("Logging is ON")

#    if dryrun():
#        print("DRYRUN mode")

    if not opts.config_file and not opts.ini_file:
        sys.exit('Error: No configuration file was provided. Please use either --ini_file or --config_file option.')
    else:
        if opts.config_file and opts.ini_file:
            sys.exit('Error: Both --ini_file and --config_file options were provided. Please use only one.')
        if opts.config_file and not os.path.isfile(opts.config_file):
            sys.exit('Error: could not find configuration file: ' + opts.config_file)
        if opts.ini_file and not os.path.isfile(opts.ini_file):
            sys.exit('Error: could not find ini file: ' + opts.config_file)

    # Information about what to run and how should be taken from configuration file
    if opts.config_file:
        cfg = Config(opts.config_file)
        cfg.read_config()
    if opts.ini_file:
        cfg = INI(opts.ini_file)
        cfg.read_config()

#    cfg.print_conf()
    do = Remanufacture(cfg.get_options())
    do.do_it_all()
