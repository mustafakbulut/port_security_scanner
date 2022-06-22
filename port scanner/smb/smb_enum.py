#!/usr/bin/env python3
#Created by unkn0wn -https://github.com/unkn-0wn


import os,sys
import subprocess

print("LINUX SMB VERSION FINDER ")
if len(sys.argv) < 3:
    print("Usage : ./smbver.py IP PORT")
else:
    ip = sys.argv[1]
    port = sys.argv[2]
    cmd='(tcpdump -s0 -n -i tun0 src '+ ip +' and port '+ port+' -A -c 10 2>/dev/null| grep -i "samba\|s.a.m" | tr -d "." | grep -oP "UnixSamba.*[0-9a-z]" & ) ; smbmap -u "" -p "" -d MYGROUP -H '+ ip +' -P '+ port +'  2>/dev/null 1>/dev/null'
    print("Getting the SMB version for you ...")
    #run = subprocess.check_output(cmd,shell=True)
    
    print("SMB VERSION : " + str(run.decode('utf-8')))