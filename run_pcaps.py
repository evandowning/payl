import errno
import os
from os import path, listdir
from os.path import isfile, join, isdir
from threading import Timer
import subprocess as sp

try:
    from subprocess import DEVNULL 
except ImportError:
    DEVNULL = open(os.devnull, 'w')

#for file in get_files_of_type(root_dir, extention): ...
def get_files_of_type(root_dir, extention):
    for root, dirs, files in os.walk(root_dir):
        for f in files:
            if f.endswith(extention):
                 yield os.path.join(root, f)

def run_p(command):
    command_list = command.split()

    p = sp.Popen(command_list, stderr = sp.PIPE, stdout = sp.PIPE, stdin = DEVNULL)
        

    kill = lambda process: process.kill()
    my_timer = Timer(5, kill, [p])

    try:
        my_timer.start()
        stdout, stderr = p.communicate()
        print(stdout)
        print(stderr)
        if 'It doesn\'t fit the model' not in stdout:
            print (command)
            input("This pcap didn't pass")
    finally:
        my_timer.cancel()
        out, err = p.communicate()
        if err:
            print (err)

for student in get_files_of_type('student_pcaps', '.pcap'):
    out = run_p('python wrapper.py ' + student)
