#!/usr/bin/env pypy
#coding:utf-8
from __future__ import unicode_literals
import os
import select
import shutil
import sys
import fcntl
import time
import subprocess
import commands
import prompt_toolkit
import argparse
import traceback
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

'''
environments of wrapper
'''
worker_dir = "/home/jungu/kafl/git-kAFL/kAFL/kAFL-Fuzzer"
exec_bin = "/bin/bash"

'''
environments of kafl
'''
fuzzer = "kafl_fuzz.py"
info = "kafl_info.py"
base_tap = "tap-"
ram_file = "/home/jungu/kafl/snapshots/win8_x64/ram.qcow2"
overlay_dir = "/home/jungu/kafl/snapshots/win8_x64/"
agent = "/home/jungu/kafl/win8/kAFL-Fuzzer/font/font_fuzzee/font_fuzzee.exe"
info_bin = "/home/jungu/kafl/bin/info.exe"
ram = "2048"
input_dir = "/home/jungu/kafl/win8/kAFL-Fuzzer/font/input_dir/"
working_dir = "/home/jungu/kafl/git-kAFL/working_dir/"

#ls /dev/shm/""" + base + """$i &> /dev/null || break
def get_valid_pal_order(base):
    cmd = """
    for((i=1;i<100;i++))
    do
        ps -ef | grep qemu | grep pal_order=${i}, &> /dev/null || break
    done

    if [ $i -eq 100 ]
    then
        echo -1
    else
        echo $i
    fi
    """
    pal_order = subprocess.check_output(cmd, shell=True, executable='/bin/bash')
    pal_order = int(pal_order.strip())
    if pal_order > 0:
        return pal_order
    else:
        print "failed to get valid pal_order"
        sys.exit(1)

def get_valid_tap(base):
    cmd = """
    for((i=2;i<50;i++))
    do
        ip link list tap-$i | grep 'state DOWN' >/dev/null 2>&1  &&  x=$i && break
    done

    if [ $i -eq 50 ]
    then
        echo -1
    else
        echo $i
    fi
    """
    tap_dev = int(os.popen(cmd).read().strip())
    if tap_dev > 0:
        return base + str(tap_dev)
    else:
        return None

"""
@dq_args: Arguments of QEMU
@dp_args: Arguments of PANDA
"""
def do_fuzz(t_env, sub_stdin=subprocess.PIPE, sub_stdout=subprocess.PIPE, sub_stderr=subprocess.PIPE):
    '''
    Constructs the argument of kafl
    '''
    if t_env.tap:
        tap_dev = base_tap + str(t_env.tap)
    else:
        tap_dev = get_valid_tap(base_tap)

    if t_env.info:
        fuzzer_exec_bin = worker_dir + "/" + info
        fuzzer_args = [fuzzer_exec_bin, ram_file, overlay_dir, info_bin, ram]
    else:
        fuzzer_exec_bin = worker_dir + "/" + fuzzer
        fuzzer_args = [fuzzer_exec_bin, ram_file, overlay_dir, agent, ram, input_dir, working_dir]

    fuzzer_args.append("-tp")
    if t_env.args:
        fuzzer_args += t_env.args.split()

    print "args of subprocess:", " ".join(fuzzer_args)
    return subprocess.Popen(fuzzer_args, stdin=sub_stdin, stdout=sub_stdout, stderr=sub_stderr)

def main():
    parser = argparse.ArgumentParser(description="Wrapper for kafl in timeplayer environment", add_help=False)
    parser.add_argument("--info", action='store_true', default=False, help="Verbose debug information")
    parser.add_argument("--args", type=str, help="Extra arguments of kafl")
    parser.add_argument("--tap", type=int, help="the serial number of tap-dev be used")

    t_env = parser.parse_args()

    r_instance = do_fuzz(t_env, None, None, None);
    r_instance.wait()
    return


if __name__ == "__main__":
    main()
    #print get_valid_pal_order(base_shm)

