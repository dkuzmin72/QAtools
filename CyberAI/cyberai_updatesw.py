import argparse
import logging
import subprocess
import glob
import sys
import pexpect
import time

CAI_NODES = ['smg-ib-apl015-gen4', 'smg-ib-apl016-gen4']
UFM_CYBERAI_DIR     = '/auto/mswg/release/ufm/cyberai/cyberai-1.0.0'
# '/auto/mswg/release/ufm/cyberai'
CAI_VERSIONS = ['1.0.0-8', '1.0.0-9']

UFM_CYBERAI_PASS    = 'UFMcyberAI'
UFM_CYBERAI_LIC     = 'mlnx-ufm-eval.lic'
UFM_UPDATE_INFO     = '' # 'update_ufm_info.sh -i 10.209.24.75 -P admin -U admin -p 443 -s qa_fabric -t https'


options = ['--quiet', '--quiet -l ' + UFM_CYBERAI_LIC, '--quiet -u ', '--quiet -u -l /tmp/' + UFM_CYBERAI_LIC]
options = ['--quiet -u -l /tmp/' + UFM_CYBERAI_LIC]

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

def main(node, version):
    logging.basicConfig(filename='check_cyber_update.log', filemode='w', format="%(asctime)s [%(levelname)s]    %(message)s", level=logging.DEBUG)
    logging.info('Start')

    add_node_to_known(node)

#    uninstall()

    old_files = get_existing_files(node)
    old_db_files = get_db_file_date(node)

    # Upgrade with no options requires interective response - should be tested manually
    # Upgrade with '--quiet' option always

    for option in options:
        #start_stop_cyberai('stop')
        if ' -u' in option:
            execute_remotely(node, 'systemctl start ufm-enterprise')
        fake_cyberai_version(node)

        upgrade_CyberAI(node, version, option)

        new_files = get_existing_files(node)
        new_db_files = get_db_file_date(node)
        check_files(old_files, new_files)
        check_db_files(old_db_files, new_db_files)

        start_stop_cyberai(node, 'start')
        time.sleep(15)
#        update_ufm_info(node)
        sanity_check(node)

        check_release_version(node, version)
        check_log_files(node)
        check_cfg_files(node)

    logging.info('End')
    print("Done!")

def add_node_to_known(node):
    print("Adding the node to known hosts...", end="")
    logging.info("Adding the node to known hosts...")
    try:
        cmd = 'ssh root@' + node
        apl = pexpect.spawn(cmd)
        apl.expect('password: ')
        apl.sendline('UFMcyberAI')
        apl.expect('~#')
        cmd = 'ssh root@r-hpc-hn01'
        apl.sendline(cmd)
        apl.expect('password', timeout = 2)
        apl.sendcontrol('c')
        apl.sendline('exit')

        logging.info("Adding the node to known hosts - Done")
        print("   Done")

    except pexpect.EOF:
        apl.sendline('yes')
        apl.sendline('exit')
        apl.sendline('exit')
        print("   added")
        logging.info("Adding the node to known hosts - Done")
    except pexpect.TIMEOUT:
        apl.sendline('yes')
        apl.sendline('exit')
        apl.sendline('exit')
        print("   added")
        logging.info("Adding the node to known hosts - Done")


def check_release_version(node, version):
    cmd = 'cat /opt/ufm/cyber-ai/version/release'
    logging.info("Checking version number after upgrade: " + cmd)
    out = execute_remotely(node, cmd)
    if version in out:
        logging.info("Version is correct")
    else:
        logging.error("Vesion is incorrect - expected: " + version + " but got: " + out)

def upgrade(node, name, option):
    print('Upgrading to ' + name)
    try:
        cmd = 'ssh root@' + node
        apl = pexpect.spawn(cmd)
        apl.expect('password: ')
        apl.sendline('UFMcyberAI')
        apl.expect('~#')
        cmd = '/tmp/' + name[:-4] + '/install.sh ' + option  # + ' >/dev/null'
        logging.info("Started upgrade: " + cmd)
        apl.sendline(cmd)
#  --quite option means that the script doesn't ask questions
#        logging.debug('Expecting: upgrade to version')
#        apl.expect('Would you like to upgrade to version')
#        apl.sendline('y')
#        if '-l ' in option:
#            logging.debug('Expecting: upgrade to UFM')
#            apl.expect('Would you like to upgrade to UFM Enterprise')
#            apl.sendline('y')
#        logging.debug('Expecting: :/')
        apl.expect('~#', timeout=600)
        out = apl.before.strip().decode('utf-8').split()
        for line in out:
            if 'please start ufm-enterprise service , using  command systemctl start ufm-enterprise' in line:
                print('GOT: please start ufm-enterprise service , using  command systemctl start ufm-enterprise')
                logging.output('please start ufm-enterprise service , using  command systemctl start ufm-enterprise')
                exit(-1)
#        print("Output:")
#        print(out)
        logging.info('Installation complete')
        print('Installation complete')

    except pexpect.EOF:
        logging.error("Upgrading CyberAI SW - Got EOF")
        print("Upgrading CyberAI SW - Got EOF")
        exit(-1)
    except pexpect.TIMEOUT:
        logging.error("Upgrading CyberAI SW - Got  TIMEOUT")
        print("Upgrading CyberAI SW - Got  TIMEOUT")
        exit(-1)


def update_ufm_info(node):
    logging.info("Updating information about UFM")
    if not len(UFM_UPDATE_INFO):
        return
    try:
        cmd = 'ssh root@' + node
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
        out = execute_remotely(node, cmd)
        logging.debug('New IP: ' + out)
        apl.sendline('exit')

    except pexpect.EOF:
        logging.error("Updating UFM info - Got EOF")
        exit(-1)
    except pexpect.TIMEOUT:
        logging.error("Updating UFM info - Got TIMEOUT")
        exit(-1)


def upgrade_CyberAI(node, version, option):
# 1 found package
# 2 check package existence in /tmp
# 3 Doesn't exist?
#   3a copy package to /tmp
#   3b untar package
# 4 run install command with needed options
    logging.info("Upgrading CyberAI on " + node + " to version " + version + " with options " + option)
    print("Upgrading CyberAI to " + version)

    remove_license_file('/opt/ufm/cyber-ai/licenses/', UFM_CYBERAI_LIC)
    clean_log_files(node)

    # Copy license file if needed
    copy_license_to_cyberai(node, '/opt/ufm/cyber-ai/licenses/', UFM_CYBERAI_LIC, option)

    # check package existance on the CyberAI machine
    path, name = get_package(version)
    exist = check_existance_on_cyberai(node, '/tmp/', name)
    if not exist:
        copy_package(node, path, name)
        exist = check_existance_on_cyberai(node, '/tmp/', name)
        if exist:
            untar_package(node, name)
        else:
            print("Could not copy SW package " + name + " to the CyberAI machine")
            logging.error("Could not copy SW package " + name + " to the CyberAI machine")
            exit(-1)
    upgrade(node, name, option)

    logging.info("Upgrade Done!")
    # Check license. In case of '-l' option it should be installed by 'install.sh' script
    exist = check_license_on_cyberai(node, UFM_CYBERAI_LIC)
    if exist:
        logging.info("License file was found")
    else:
        logging.error("License file was not found in /opt/ufm/cyber-ai/licenses")
        exit(-1)
    return name



def clean_log_files(node):
    print("Cleaning log files")
    logging.debug("Cleaning log files")
    for file in log_files:
        cmd = 'true \> /var/log/cyberai/' + file
        out = execute_remotely(node, cmd)

def remove_license_file(path, lic_file):
    print("Removing license file")
    logging.debug("Removing license file")
    cmd = 'rm -f ' + path + '/' + lic_file
    out = execute_remotely(node, cmd)

def copy_license(node, path, lic_file):
    print("Copying license file to " + path, end="")
    logging.debug("Copying license file")
    try:
        cmd = 'ssh root@' + node
        apl = pexpect.spawn(cmd)
        apl.expect('password: ')
        apl.sendline('UFMcyberAI')
        apl.expect('~#')
        if lic_file:
            cmd = 'scp root@r-hpc-hn01:/hpc/local/work/dmitryk/workspace/GET_CollectX_LICENSE/' + lic_file + ' ' + path #' /opt/ufm/cyber-ai/licenses/'
#        else:
#            cmd = 'scp dkuzmin@r-hpc-hn01:/auto/UFM/cyber-ai/lic/mlnx-ufm-apl' + str(idx).rjust(3, '0') + '_dk.lic ' + path  #/opt/ufm/cyber-ai/licenses/'
        logging.debug("Copying the license file: " + cmd)
        apl.sendline(cmd)
        apl.expect('password: ')
        apl.sendline('3tango')
        apl.expect('~#')
        apl.sendline('exit')
        print("    Done")

    except pexpect.EOF:
        print("    ERROR - got EOF")
        logging.error("Copying license file - Got EOF")
        exit(-1)
    except pexpect.TIMEOUT:
        print("    ERROR - got TIMEOUT")
        logging.error("Copying license file - Got  TIMEOUT")
        exit(-1)

def copy_license_to_cyberai(node, path, lic_file, option=""):
#    print("Copying license file... ", end="")
    logging.debug("Copying license file with option: " + option)
    # First be sure that we have a license file ini /tmp directory which will be used for '-l' option
    exist = check_existance_on_cyberai(node, '/tmp/', lic_file)
    if not exist:
        copy_license(node, '/tmp/', lic_file)

    # If we use 'install.sh' w/o '-l _lic_file_' opiton we need to copy lic file manually
    if '-l ' not in option:
        exist = check_existance_on_cyberai(node, path, lic_file)
        if not exist:
            copy_license(node, path, lic_file)


def check_license_on_cyberai(node, lic_file):
    print("Checking license file")
    logging.debug("Checking license file")
    exist = check_existance_on_cyberai(node, '/opt/ufm/cyber-ai/licenses/', lic_file)
    if exist:
        return True

    exist = check_existance_on_cyberai(node, '/tmp/', UFM_CYBERAI_LIC)
    if not exist:
        copy_license(node, '/tmp/', UFM_CYBERAI_LIC)

    return False


def check_existance_on_cyberai(node, path, file_name):
    print("Checking existance of " + path + file_name, end="")
    logging.debug("Checking existance of " + path + file_name)
    cmd = 'ls ' + path + '/' + file_name + ' 2>/dev/null'
    out = execute_remotely(node, cmd)
    if file_name in out:
        logging.debug("Found file " + file_name + " in " + path)
        print("    Found")
        return True
    logging.debug("There is no file " + file_name + " in " + path)
    print("    Not found")
    return False

def fake_cyberai_version(node):
    # to avoid real install of old version we can substitute 'release' file
    # 0.9.3-7 version doesn't support 'UPGRADE' mode - it requires uninstall and it means that we can lose all data
    cmd = '\'echo 0.9.3-7 > /opt/ufm/cyber-ai/version/release\''
    out = execute_remotely(node, cmd)

def execute(cmd):
    logging.debug("Executing: " + cmd)
    out = ""
    exe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = exe.stdout.read().strip().decode('utf-8')
#    logging.debug("Output: " + out)
    return out

def execute_remotely(node, cmd):
    remote_ssh = 'sshpass -p ' + UFM_CYBERAI_PASS + ' ssh root@' + node
    cmd = remote_ssh + ' ' + cmd
    out = execute(cmd)
    return out

def get_list_of_files(node, path, dir):
    cmd = 'ls ' + path + '/' + dir
    out = execute_remotely(node, cmd)
    return out.split()

def get_db_file_date(node):
    cmd = 'ls -l /opt/ufm/cyber-ai/datastore/databases/cyberai.db'
    out = execute_remotely(node, cmd)
    fields = out.split()
    date_time = fields[4] + fields[5] + fields[6] + ' ' + fields[7]
    return date_time

def get_existing_files(node):
    all_files = []
    for p in pathes:
        for d in dirs[p]:
            files = get_list_of_files(node, p, d)
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

def check_log_files(node):
    print("Checking log files for exceptions")
    logging.debug("Checking log files for exceptions")
    for file in log_files:
        cmd = 'grep exception /var/log/cyberai/' + file
        out = execute_remotely(node, cmd)
        if 'exception' in out:
            logging.error("FAILED: there is an exception in /var/log/cyberai/" + file)
        else:
            logging.info("PASSED: there is no exception in " + file)
        cmd = 'grep Traceback /var/log/cyberai/' + file
        out = execute_remotely(node, cmd)
        if 'Traceback' in out:
            logging.error("FAILED: there is a Traceback in /var/log/cyberai/" + file)
        else:
            logging.info("PASSED: there is no Traceback in " + file)

def check_cfg_files(node):
    print("Checking cfg files for new secitons")
    logging.debug("Checking cfg files for new secitons")
    cfg_file = '/opt/ufm/cyber-ai/conf/cyberai.cfg'
    for section in new_sections:
        cmd = 'grep -F ' + section + ' ' + cfg_file
        out = execute_remotely(node, cmd)
        if section in out:
            logging.info("PASSED: new section " + section + " is in cyberai.cfg")
        else:
            print("FAILED: could not find section: " + section + " in /opt/ufm/cyber-ai/conf/cyber.cfg")
            logging.error("FAILED: could not find section: " + section + " in /opt/ufm/cyber-ai/conf/cyber.cfg")

def get_docker_id(node, docker_name):
    cmd = 'docker ps | grep ' + docker_name
    out = execute_remotely(node, cmd)
    docker_id = ""
    if out:
        docker_id = out.split()[0]
    return docker_id


def get_package(version):
    version = 'sw-' + version + '.tar'
    print("Getting package for version: " + version )
    logging.debug("Getting package for version: " + version )
    regexp = UFM_CYBERAI_DIR + '/*' + version + '*'
    files = glob.glob(regexp)
    if len(files) == 0:
        print("Error: Could not find SW package for CyberAI version: " + str(version))
        logging.error("Error: Could not find SW package for CyberAI version: " + str(version))
        sys.exit(-1)
    if len(files) == 1:
        path,delim,name = files[0].rpartition('/')
        logging.debug("SW package: " + name + " is located in " + path + " directory")
        return (path, name)
    else:
        print("Error: Found too many files suitable for the version in " + UFM_CYBERAI_DIR + ": "+ str(version))
        logging.error("Error: Found too many files suitable for the version in " + UFM_CYBERAI_DIR + ": "+ str(version))
        sys.exit(-1)

def check_md5(node, path, name):
    logging.debug("Checking md5")
    cmd = "md5sum " + path + "/" + name
    md5_orig = execute(cmd)
    md5_orig = md5_orig.split()[0]
    cmd = "md5sum " + "/tmp/" + name
    md5_new = execute_remotely(node, cmd)
    md5_new = md5_new.split()[0]
    if not md5_orig == md5_new:
        print("Incorrect MD5 sum - please remove /tmp/" + name + " file manually")
        print("Original: " + md5_orig + " after copy: " + md5_new)
        logging.error("Incorrect MD5 sum - aborted")
        exit(-1)
    print("Original md5: " + md5_orig + " after copy: " + md5_new)
    print("MD5 is OK")
    logging.info("MD5 original: " + md5_orig + " after copy: " + md5_new + " - OK!")

def copy_package(node, path, name):
    print("Copying package " + name + " to " + node, end="")
    logging.info("Copying package " + name + " to CyberAI machine")
    try:
        cmd = 'ssh root@' + node
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
        print("    Done")

    except pexpect.EOF:
        print("    ERROR - Got EOF")
        logging.error("Copying SW package - Got EOF")
        exit(-1)
    except pexpect.TIMEOUT:
        print("    ERROR - Got TIMEOUT")
        logging.error("Copying SW package - Got TIMEOUT")
        exit(-1)

    check_md5(node, path, name)

def untar_package(node, name):
    print("Unpacking the package... ", end="")
    logging.debug("Unpacking the package")
    cmd = 'tar xvf /tmp/' + name + ' -C /tmp'
    out = execute_remotely(node, cmd)
    print("    Done")


def is_cyberai_running(node):
    cmd = ' service ufm-cyberai status | grep Active'
    out = execute_remotely(node, cmd)
    if 'running' in out:
        return True
    return False



def start_stop_cyberai(node, do):
    if do not in ['start', 'stop']:
        logging.error("Unsupported action: " + do)
        exit(-1)
    cmd = ' service ufm-cyberai ' + do
    out = execute_remotely(node, cmd)
    if do == 'start':
        if is_cyberai_running(node):
            logging.debug("CyberAI service is running")
            print("CyberAI service is UP")
        else:
            logging.info("Starting CyberAI service and sleep 30 sec")
            print("Starting CyberAI and sleep 30 sec")
            time.sleep(30)
    else:
        print("Stopping CyberAI service")


def uninstall(node):
    print("Uninstalling CyberAI...")
    logging.info("Uninstalling CyberAI...")
    exist = check_existance_on_cyberai(node, "/opt/ufm/cyber-ai/", "uninstall.sh")
    if not exist:
        print("Already uninstalled - nothing to do")
        logging.info("Already uninstalled - nothing to do")
        return
    try:
        cmd = 'ssh root@' + node
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
        apl.expect('~#', timeout=180)
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
    out = execute_remotely(node, cmd)
    logging.debug("Images after uninstallation")
    logging.debug(out)

def sanity_check(node):
    print("Running sanity check...", end="")
    logging.debug("Running sanity check")
    cmd = 'ufm_cyberai_sanity.sh'
    time.sleep(15)
    out = execute_remotely(node, cmd)
    if "Error:" in out:
        logging.warning("First attempt of Sanity check didn't pass. Let's wait 30 sec")
        time.sleep(30)
        out = execute_remotely(node, cmd)
        if "Error:" in out:
            print("    ERROR - see log file")
            logging.error("FAILED: Sanity check didn't pass")
        else:
            print("    Passed after 30 sec")
            logging.info("PASSED: Sanity check passed after 30 sec")
    else:
        print("    Passed")
        logging.info("PASSED: Sanity script")



if __name__ == "__main__":
    choice = ''
    print('We can upgrade CyberAI SW on the following nodes:')
    i = 1
    for node in CAI_NODES:
        print('    ' + str(i) + ': ' + node)
        i += 1
    while not choice:
        choice = input('Enter your choice: ')
        if not choice or not (int(choice) > 0 and int(choice) <= len(CAI_NODES)):
            print('Incorrect choice')
            choice = ''
#    print('You selected ' + CAI_NODES[int(choice) - 1])
    node = CAI_NODES[int(choice) - 1]

    choice = ''
    print('We can upgrade CyberAI SW to the following version:')
    i = 1
    for ver in CAI_VERSIONS:
        print('    ' + str(i) + ': ' + ver)
        i += 1
    while not choice:
        choice = input('Enter your choice: ')
        if not choice or not (int(choice) > 0 and int(choice) <= len(CAI_VERSIONS)):
            print('Incorrect choice')
            choice = ''
#    print('You selected ' + CAI_VERSIONS[int(choice) - 1])
    ver = CAI_VERSIONS[int(choice) - 1]

#    node = ''
#    args = argparse.ArgumentParser(description='This script installs Cyber AI SW package on a CyberAI machine')
#    args.add_argument("node_name", type=str, help="Nodename")
#    args.add_argument("version",   type=str, help="CyberAI version in the format 1.0.0-9")
#    args.add_argument("-m", "--machine", action='store', help="Cyber AI machine index. Pattern is: smg-ib-aplIDX-gen3")
#    args.add_argument("-l", "--license", action='store', help="License file for this machine. Default location is /auto/UFM/cyber-ai/lic/")
#    args.add_argument("-u", "--upgrade", action='store_true', help="Do upgrade instead of installation. Installation removes old data.")

#    opts = args.parse_args()
#    node = opts.node_name
#    ver  = opts.node_name

#    cyber = Install_CyberAI(opts)
#    cyber.do_it()

#    print(node)
    main(node, ver)
