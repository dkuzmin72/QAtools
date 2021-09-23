import argparse
import logging
import subprocess
import glob
import sys
import pexpect
import time

UFM_CYBERAI_MACHINE = 'smg-ib-apl015-gen3'
UFM_CYBERAI_DIR     = '/auto/mswg/release/ufm/cyberai'
UFM_CYBERAI_PASS    = 'UFMcyberAI'
UFM_CYBERAI_VER     = '0.9.4-10'
UFM_CYBERAI_LIC     = 'mlnx-ufm-apl015_dk.lic'
UFM_UPDATE_INFO     = 'update_ufm_info.sh -i 10.209.24.75 -P admin -U admin -p 443 -s qa_fabric -t https'

remote_ssh = 'sshpass -p ' + UFM_CYBERAI_PASS + ' ssh root@' + UFM_CYBERAI_MACHINE

options = ['--quiet', '--quiet -l /tmp/mlnx-ufm-apl015_dk.lic', '--quiet -u ', '--quiet -u -l /tmp/' + UFM_CYBERAI_LIC]
#options = ['--quiet ']

pathes = [
'/opt/ssd_data/cyber-ai/datastore/aggregation/',
'/opt/ssd_data/ufm-telemetry/data/2021/',
'/opt/ssd_data/cyber-ai/datastore/' ]
#'/opt/ufm/cyber-ai/' ]

log_files = ['console.log', 'cyberai.log', 'jobs_stats.log', 'rest.log']

dirs = {}
dirs[pathes[0]] = ['anomalies', 'cable_anomalies', 'delta', 'dow', 'hourly', 'ml_hourly', 'network_anomalies', 'network_dow', 'network_hourly', 'pkey', 'pkey_join_port', 'port_counters', 'split', 'topology', 'weekly']
dirs[pathes[1]] = ['0922']
dirs[pathes[2]] = ['network']
#dirs[pathes[2]] = ['licenses'] - license file may  be there or may be not

new_sections = ['[JobSettings]', '[JobSettings::timeout]', 'health_check_interval']

def main():
    logging.basicConfig(filename='check_cyber_update.log', filemode='w', format="%(asctime)s [%(levelname)s]    %(message)s", level=logging.DEBUG)
    logging.info('Start')

    start_stop_cyberai('stop')

#    uninstall()

    old_files = get_existing_files()
    old_db_files = get_db_file_date()

    # Upgrade with no options requires interective response - should be tested manually
    # Upgrade with '--quiet' option always

    for option in options:
        start_stop_cyberai('stop')
        fake_cyberai_version()

        upgrade_CyberAI(UFM_CYBERAI_VER, option)

        new_files = get_existing_files()
        new_db_files = get_db_file_date()
        check_files(old_files, new_files)
        check_db_files(old_db_files, new_db_files)

        start_stop_cyberai('start')
        time.sleep(15)
#        update_ufm_info(UFM_CYBERAI_MACHINE)
        sanity_check()

        check_log_files()
        check_cfg_files()

    logging.info('End')
    print("Done!")

def upgrade(name, option):
    print('Upgrading to ' + name)
    cmd = '/tmp/' + name[:-4] + '/install.sh ' + option  # + ' >/dev/null'
    logging.info("Started upgrade: " + cmd)
    out = execute_remotely(cmd)

def update_ufm_info(machine):
    logging.info("Updating information about UFM")
    try:
        cmd = 'ssh root@' + machine
        apl = pexpect.spawn(cmd)
        apl.expect('password: ')
        apl.sendline(UFM_CYBERAI_PASS)
        apl.expect('~#')
        logging.debug("Running update_ufm_info.sh command")
        apl.sendline(UFM_UPDATE_INFO)
        apl.expect('~#')
        out = apl.before.strip().decode('utf-8')
        logging.debug("Update UFM out: " + out)
        apl.sendline("echo $?")
        apl.expect('~#')
        exitcode = apl.before.strip().decode('utf-8')
        logging.debug("Update UFM info exit code = " + exitcode)
        cmd = 'grep ip /opt/ufm/cyber-ai/conf/ufm_connection_params.json'
        out = execute_remotely(cmd)
        logging.debug('New IP: ' + out)
        apl.sendline('exit')

    except pexpect.EOF:
        logging.error("Updating UFM info - Got EOF")
        exit(-1)
    except pexpect.TIMEOUT:
        logging.error("Updating UFM info - Got TIMEOUT")
        exit(-1)


def upgrade_CyberAI(version, option):
# 1 found package
# 2 check package existence in /tmp
# 3 Doesn't exist?
#   3a copy package to /tmp
#   3b untar package
# 4 run install command with needed options
    logging.info("Upgrading CyberAI to version " + version + " with options " + option)
    print("Upgrading CyberAI to " + version)

    remove_license_file('/opt/ufm/cyber-ai/licenses/', UFM_CYBERAI_LIC)
    clean_log_files()

    # Copy license file if needed
    copy_license_to_cyberai(UFM_CYBERAI_MACHINE, '/opt/ufm/cyber-ai/licenses/', UFM_CYBERAI_LIC, option)

    # check package existance on the CyberAI machine
    path, name = get_package(version)
    exist = check_existance_on_cyberai('/tmp/', name)
    if not exist:
        copy_package(UFM_CYBERAI_MACHINE, path, name)
        exist = check_existance_on_cyberai('/tmp/', name)
        if exist:
            untar_package(name)
        else:
            logging.error("Could not copy SW package " + name + " to the CyberAI machine")
            exit(-1)
    upgrade(name, option)

    logging.info("Upgrade Done!")
    # Check license. In case of '-l' option it should be installed by 'install.sh' script
    exist = check_license_on_cyberai(UFM_CYBERAI_LIC)
    if exist:
        logging.info("License file was found")
    else:
        logging.error("License file was not found in /opt/ufm/cyber-ai/licenses")
        exit(-1)
    return name



def clean_log_files():
    print("Cleaning log files")
    logging.debug("Cleaning log files")
    for file in log_files:
        cmd = 'true \> /var/log/cyberai/' + file
        out = execute_remotely(cmd)

def remove_license_file(path, lic_file):
    print("Removing license file")
    logging.debug("Removing license file")
    cmd = 'rm -f ' + path + '/' + lic_file
    out = execute_remotely(cmd)


def copy_license_to_cyberai(machine, path, lic_file, option=""):
    print("Copying license file")
    logging.debug("Copying license file")
    # First be sure that we have a license file ini /tmp directory which will be used for '-l' option
    exist = check_existance_on_cyberai('/tmp/', lic_file)
    if not exist:
        copy_license(machine, '/tmp/', lic_file)

    # If we use 'install.sh' w/o '-l _lic_file_' opiton we need to copy lic file manually
    if 'license' not in option:
        exist = check_existance_on_cyberai(path, lic_file)
        if not exist:
            copy_license(machine, path, lic_file)


def check_license_on_cyberai(lic_file):
    print("Checking license file")
    logging.debug("Checking license file")
    exist = check_existance_on_cyberai('/opt/ufm/cyber-ai/licenses', lic_file)
    if exist:
        return True

    exist = check_existance_on_cyberai('/tmp/', UFM_CYBERAI_LIC)
    if not exist:
        copy_license(UFM_CYBERAI_MACHINE)

    return False


def check_existance_on_cyberai(path, file_name):
    print("Checking existance of " + path + file_name)
    logging.debug("Checking existance of " + path + file_name)
    cmd = 'ls ' + path + '/' + file_name + ' 2>/dev/null'
    out = execute_remotely(cmd)
    if file_name in out:
        logging.debug("Found file " + file_name + " in " + path)
        print("Found")
        return True
    logging.debug("There is no file " + file_name + " in " + path)
    print("Not found")
    return False

def fake_cyberai_version():
    # to avoid real install of old version we can substitute 'release' file
    # 0.9.3-7 version doesn't support 'UPGRADE' mode - it requires uninstall and it means that we can lose all data
    cmd = '\'echo 0.9.3-7 > /opt/ufm/cyber-ai/version/release\''
    out = execute_remotely(cmd)

def execute(cmd):
    logging.debug("Executing: " + cmd)
    out = ""
    exe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = exe.stdout.read().strip().decode('utf-8')
#    logging.debug("Output: " + out)
    return out

def execute_remotely(cmd):
    cmd = remote_ssh + ' ' + cmd
    out = execute(cmd)
    return out

def get_list_of_files(path, dir):
    cmd = 'ls ' + path + '/' + dir
    out = execute_remotely(cmd)
    return out.split()

def get_db_file_date():
    cmd = 'ls -l /opt/ufm/cyber-ai/datastore/databases/cyberai.db'
    out = execute_remotely(cmd)
    fields = out.split()
    date_time = fields[4] + fields[5] + fields[6] + ' ' + fields[7]
    return date_time

def get_existing_files():
    all_files = []
    for p in pathes:
        for d in dirs[p]:
            files = get_list_of_files(p, d)
            #print(files)
            all_files.append(files)

    return all_files

def check_files(old_files, new_files):
    print("Checking files")
    logging.debug("Checking files")
    check =  all(item in old_files for item in new_files)
    if check:
        logging.info('PASSED: All existing files were preserved')
    else:
        logging.error('FAILED: Not all files were preserved after upgrade')
        logging.debug('Old files: ' + str(old_files))
        logging.debug('New files: ' + str(new_files))

def check_db_files(old_db, new_db):
    print("Checking DB file")
    logging.debug("Checking DB file")
    if old_db != new_db:
        logging.error('FAILED: DB file /opt/ufm/cyber-ai/datastore/databases/cyberai.db was changed - was: ' + old_db + ' new: ' + new_db)
    else:
        logging.info('PASSED: Old and new DB files are the same')

def check_log_files():
    print("Checking log files for exceptions")
    logging.debug("Checking log files for exceptions")
    for file in log_files:
        cmd = 'grep exception /var/log/cyberai/' + file
        out = execute_remotely(cmd)
        if 'exception' in out:
            logging.error("FAILED: there is an exception in /var/log/cyberai/" + file)
        else:
            logging.info("PASSED: there is no exception in " + file)
        cmd = 'grep Traceback /var/log/cyberai/' + file
        out = execute_remotely(cmd)
        if 'Traceback' in out:
            logging.error("FAILED: there is a Traceback in /var/log/cyberai/" + file)
        else:
            logging.info("PASSED: there is no Traceback in " + file)

def check_cfg_files():
    print("Checking cfg files for new secitons")
    logging.debug("Checking cfg files for new secitons")
    cfg_file = '/opt/ufm/cyber-ai/conf/cyberai.cfg'
    for section in new_sections:
        cmd = 'grep -F ' + section + ' ' + cfg_file
        out = execute_remotely(cmd)
        if section in out:
            logging.info("PASSED: new section " + section + " is in cyberai.cfg")
        else:
            logging.error("FAILED: could not find section: " + section + " in /opt/ufm/cyber-ai/conf/cyber.cfg")

def get_docker_id(docker_name):
    cmd = 'docker ps | grep ' + docker_name
    out = execute_remotely(cmd)
    docker_id = ""
    if out:
        docker_id = out.split()[0]
    return docker_id


def get_package(version):
    print("Getting package for version: " + version )
    logging.debug("Getting package for version: " + version )
    regexp = UFM_CYBERAI_DIR + '/*' + str(version) + '*'
    files = glob.glob(regexp)
    if len(files) == 0:
        logging.error("Error: Could not find SW package for CyberAI version: " + str(version))
        sys.exit(-1)
    if len(files) == 1:
        path,delim,name = files[0].rpartition('/')
        logging.debug("SW package: " + name + " is located in " + path + " directory")
        return (path, name)
    else:
        logging.error("Error: Found too many files suitable for the version in " + UFM_CYBERAI_DIR + ": "+ str(version))
        sys.exit(-1)

def check_md5(path, name):
    logging.debug("Checking md5")
    cmd = "md5sum " + path + "/" + name
    md5_orig = execute(cmd)
    md5_orig = md5_orig.split()[0]
    cmd = "md5sum " + "/tmp/" + name
    md5_new = execute_remotely(cmd)
    md5_new = md5_new.split()[0]
    if not md5_orig == md5_new:
        print("Incorrect MD5 sum - please remove /tmp/" + name + " file manually")
        print("Original: " + md5_orig + " after copy: " + md5_new)
        logging.error("Incorrect MD5 sum - aborted")
        exit(-1)
    print("Original md5: " + md5_orig + " after copy: " + md5_new)
    print("MD5 is OK")
    logging.info("MD5 original: " + md5_orig + " after copy: " + md5_new + " - OK!")

def copy_package(machine, path, name):
    print("Copying package " + name + " to CyberAI machine")
    logging.info("Copying package " + name + " to CyberAI machine")
    try:
        cmd = 'ssh root@' + machine
        apl = pexpect.spawn(cmd)
        apl.expect('password: ')
        apl.sendline('UFMcyberAI')
        apl.expect('~#')
        apl.sendline('cd /tmp')
        apl.expect('tmp#')
        cmd = 'scp dkuzmin@r-hpc-hn01:' + path + "/" + name + " /tmp"
        logging.debug("Copying package to /tmp: " + cmd)
        apl.sendline(cmd)
        apl.expect('password: ')
        apl.sendline('dkuzmin11')
        apl.expect('tmp#', timeout=120)
        time.sleep(5)
        apl.sendline('exit')

        logging.info("Copying package " + name + " to CyberAI machine Done!")

    except pexpect.EOF:
        logging.error("Copying SW package - Got EOF")
        exit(-1)
    except pexpect.TIMEOUT:
        logging.error("Copying SW package - Got TIMEOUT")
        exit(-1)

    check_md5(path, name)

def untar_package(name):
    print("Untar package")
    logging.debug("Untar package")
    cmd = 'tar xvf /tmp/' + name + ' -C /tmp'
    out = execute_remotely(cmd)

def copy_license(machine, path, lic_file):
    print("Copying license file")
    logging.debug("Copying license file")
    try:
        cmd = 'ssh root@' + machine
        apl = pexpect.spawn(cmd)
        apl.expect('password: ')
        apl.sendline('UFMcyberAI')
        apl.expect('~#')
        if lic_file:
            cmd = 'scp dkuzmin@r-hpc-hn01:/auto/UFM/cyber-ai/lic/' + lic_file + ' ' + path #' /opt/ufm/cyber-ai/licenses/'
#        else:
#            cmd = 'scp dkuzmin@r-hpc-hn01:/auto/UFM/cyber-ai/lic/mlnx-ufm-apl' + str(idx).rjust(3, '0') + '_dk.lic ' + path  #/opt/ufm/cyber-ai/licenses/'
        logging.debug("Copying the license file: " + cmd)
        apl.sendline(cmd)
        apl.expect('password: ')
        apl.sendline('dkuzmin11')
        apl.expect('~#')
        apl.sendline('exit')

    except pexpect.EOF:
        logging.error("Copying license file - Got EOF")
        exit(-1)
    except pexpect.TIMEOUT:
        logging.error("Copying license file - Got  TIMEOUT")
        exit(-1)

def is_cyberai_running():
    cmd = ' service ufm-cyberai status | grep Active'
    out = execute_remotely(cmd)
    if 'running' in out:
        return True
    return False



def start_stop_cyberai(do):
    if do not in ['start', 'stop']:
        logging.error("Unsupported action: " + do)
        exit(-1)
    cmd = ' service ufm-cyberai ' + do
    out = execute_remotely(cmd)
    if do == 'start':
        if is_cyberai_running():
            logging.debug("CyberAI service is running")
            print("CyberAI service is UP")
        else:
            logging.info("Starting CyberAI service and sleep 30 sec")
            print("Starting CyberAI and sleep 30 sec")
            time.sleep(30)
    else:
        print("Stopping CyberAI service")


def uninstall():
    print("Uninstalling CyberAI...")
    logging.info("Uninstalling CyberAI...")
    exist = check_existance_on_cyberai("/opt/ufm/cyber-ai/", "uninstall.sh")
    if not exist:
        print("Already uninstalled - nothing to do")
        logging.info("Already uninstalled - nothing to do")
        return
    try:
        cmd = 'ssh root@' + UFM_CYBERAI_MACHINE
        apl = pexpect.spawn(cmd)
        apl.expect('password: ')
        apl.sendline('UFMcyberAI')
        apl.expect('~#')
#        cmd = 'cd /tmp/' + name[:-4]
#            print("Changing dir ", cmd)
#        apl.sendline(cmd)
#        apl.expect('tmp/')

        apl.sendline('/opt/ufm/cyber-ai/uninstall.sh -u')
        apl.expect('Cyber-AI')
        apl.sendline('y')
        apl.expect('~#')
#        apl.expect('tmp/')

        apl.sendline('exit')

        print("Uninstallation Done!")
        logging.info("Uninstalling CyberAI...  Done!")

    except pexpect.EOF:
        print("Uninstalling SW package to - Got EOF")
        logging.error("Uninstalling SW package - Got EOF")
        exit(-1)
    except pexpect.TIMEOUT:
        print("Uninstalling SW package -  Got TIMEOUT")
        logging.error("Uninstalling SW package -  Got TIMEOUT")
        exit(-1)

    cmd = 'docker images'
    out = execute_remotely(cmd)
    logging.debug("Images after uninstallation")
    logging.debug(out)

def sanity_check():
    print("Running sanity check")
    logging.debug("Running sanity check")
    cmd = 'ufm_cyberai_sanity.sh'
    time.sleep(15)
    out = execute_remotely(cmd)
    if "Error:" in out:
        logging.warning("First attempt of Sanity check didn't pass. Let's wait 30 sec")
        time.sleep(30)
        out = execute_remotely(cmd)
        if "Error:" in out:
            logging.error("FAILED: Sanity check didn't pass")
        else:
            logging.info("PASSED: Sanity check passed after 30 sec")
    else:
        logging.info("PASSED: Sanity script")



if __name__ == "__main__":
    main()

#    args = argparse.ArgumentParser(description='This script installs Cyber AI SW package on a CyberAI machine')
#    args.add_argument("-v", "--version", action='store', help="SW package version to look for. For example 9.3-3")
#    args.add_argument("-m", "--machine", action='store', help="Cyber AI machine index. Pattern is: smg-ib-aplIDX-gen3")
#    args.add_argument("-l", "--license", action='store', help="License file for this machine. Default location is /auto/UFM/cyber-ai/lic/")
#    args.add_argument("-u", "--upgrade", action='store_true', help="Do upgrade instead of installation. Installation removes old data.")

#    opts = args.parse_args()

#    cyber = Install_CyberAI(opts)
#    cyber.do_it()

