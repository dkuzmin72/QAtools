import argparse
import logging
import subprocess
import glob
import sys
import pexpect
import time

UFM_CYBERAI_MACHINE = 'smg-ib-apl015-gen3'
UFM_CYBERAI_PASS    = 'UFMcyberAI'

remote_ssh = 'sshpass -p ' + UFM_CYBERAI_PASS + ' ssh root@' + UFM_CYBERAI_MACHINE

dockers = ['cyberai-web', 'ufm-telemetry']

def main():
    logging.basicConfig(filename='check_cyber_healthmonitor.log', filemode='w', format="%(asctime)s [%(levelname)s]    %(message)s", level=logging.DEBUG)
    logging.info('Start')

    start_stop_cyberai('start')

    check_health_monitoring()

    logging.info('End')
    print("Done!")

def check_health_monitoring():
    # idea for health monitoring:
    # kill a process and check that this process is UP again in N seconds
    # health monitoring process scan dockers and processesses each 2 minutes (configurable)
    # Health Monitoring checks:
    # cyberai-web docker
    # ufm-telemetry docker: 
    #     ‘ps -fade’ and verify that all these processes are running:
    #         ‘agx, clx, supervisord, agx_manager.py, agx_server.py, launch_ibdiagnet.py, launch_retention.py, launch_compression.py, launch_cableinfo.py’
    # inside of cyberai-plm:
    # there is main process: cyberai_proc.pyc

    # Stop dockers
    for docker in dockers:
        print("Stopping docker " + docker)
        logging.info("Stopping docker " + docker)
        cmd = 'docker container stop ' + docker
        execute_remotely(cmd)

    pid1 = get_cyberai_proc_pid()
    stop_cyberai_proc(pid1)

    print("Sleeping for 2 minutes")
    time.sleep(130) # defualt timeout is 2 minutes.

    pid2 = get_cyberai_proc_pid()

    print("Initial PID: " + pid1 + "  New PID: " + pid2)
    if pid2 and pid2 != pid1:
        logging.info("PASSED: Health Monitoring restored cyberai_proc.pyc process")
    else:
        logging.error("FAILED: Health Monitoring did not restore cyberai_proc.pyc process")

    for docker in dockers:
        id = get_docker_id(docker)
        if id:
            print("Docker " + docker + " was restored")
            logging.info("PASSED: docker " + docker + " is UP and running")
        else:
            print("Docker " + docker + " was NOT restored")
            logging.error("FAILED: docker " + docker + " is not running. Health Monitoring doesn't work properly.")



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


def get_docker_id(docker_name):
    cmd = 'docker ps | grep ' + docker_name
    out = execute_remotely(cmd)
    docker_id = ""
    if out:
        docker_id = out.split()[0]
    return docker_id

def stop_cyberai_proc(pid):
    print("Stopping cyberai_proc process")
    try:
        cmd = 'ssh root@' + UFM_CYBERAI_MACHINE
        apl = pexpect.spawn(cmd)
        apl.expect('password: ')
        apl.sendline(UFM_CYBERAI_PASS)
        apl.expect('~#')
        cmd = 'docker exec -ti cyberai-plm bash'
        apl.sendline(cmd)
        apl.expect('/#')
        cmd = 'kill -9 ' + pid
        apl.sendline(cmd)
        apl.expect('/#')
#        print(apl.before.decode('utf-8'))
        apl.sendline('exit')

    except pexpect.EOF:
        logging.error("Stopping cyberai_proc - Got EOF")
        exit(-1)
    except pexpect.TIMEOUT:
        logging.error("Stopping cyberai_proc - Got  TIMEOUT")
        exit(-1)

def get_cyberai_proc_pid():
    print("Getting cyberai_proc pid")
    try:
        cmd = 'ssh root@' + UFM_CYBERAI_MACHINE
        apl = pexpect.spawn(cmd)
        apl.expect('password: ')
        apl.sendline(UFM_CYBERAI_PASS)
        apl.expect('~#')
        cmd = 'docker exec -ti cyberai-plm bash'
        apl.sendline(cmd)
        apl.expect('/#')
        cmd = 'ps aux | grep _proc | head -1'
        apl.sendline(cmd)
        apl.expect('/#')
        print(apl.before.decode('utf-8').split('\n'))
        if len(apl.before.decode('utf-8').split('\n')):
            pid = apl.before.decode('utf-8').split('\n')[1]
        else:
            logging.error("Could not find proper PID")
            return 0
        logging.debug("Parsing pid, got: " + pid)
        pid = pid.split()[1]
        logging.info("extracted PID: " + pid)
        apl.sendline('exit')

        return pid

    except pexpect.EOF:
        logging.error("Stopping cyberai_proc - Got EOF")
        exit(-1)
    except pexpect.TIMEOUT:
        logging.error("Stopping cyberai_proc - Got  TIMEOUT")
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
            logging.info("CyberAI service is already running")
            print("CyberAI service is UP")
        else:
            logging.info("Starting CyberAI service and sleep 30 sec")
            print("Starting CyberAI and sleep 30 sec")
            time.sleep(30)
    else:
        print("Stopping CyberAI service")


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





