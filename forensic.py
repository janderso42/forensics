#! /bin/python
#Requires scalpel, foremost
import os.path
import argparse
import subprocess
import random
import re

parser = argparse.ArgumentParser(description='Python forensic automation')
parser.add_argument('image', help='Disk Image to Analyze')   #target
parser.add_argument('-f', action='store_true', help='Perform data recovery with Scalpel. Requires path to conf file')
parser.add_argument('-conf', action='store', dest='scalp', help='Provide a path to a scalpel conf file')
parser.add_argument('-l', action='store_true', help='Pull authentication log info from wtmp')
parser.add_argument('-m', action='store_true', help='Leave image mounted for manual investigation')
iput = parser.parse_args()

if os.getuid() != 0:
    exit("Error: Forensic script needs to be run with root permissions")

if os.path.isfile(iput.image) == False:         ##If image does not exist
    print "Error: Disk image not found\nExiting..."
    exit()

print "Mounting %s" % (iput.image)
try:                                            ##Partitions 
    command = ['kpartx', '-av', iput.image]
    p=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err=p.communicate()
except:
    out, err=p.communicate()
    print err
    print out
    print "There was a problem creating the loopback devices for the partions"
    exit()

splitOut = [w for w in re.split('\W', out) if w]
loops=['loop0p1', 'loop0p2']
print "Loopback devices created for all partitions"

dir1="/mnt/"+str(random.randint(100,999))
dir2="/mnt/"+str(random.randint(100,999))

try:                                            ##make directories and mount
    command = ['mkdir',dir1, dir2]
    p=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err=p.communicate()
    command=['mount', '-oro', '/dev/mapper/'+loops[0], dir1]
    p=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err=p.communicate()
    command=['mount', '-oro', '/dev/mapper/'+loops[1], dir2]
    p=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err=p.communicate()
except:
    print err
    print out
    print "There was a problem mounting the partitions"
    command = ['rm', '-r', dir1, dir2]
    p=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    exit()

print "Partitions mounted to %s and %s" % (dir1, dir2)

shell={}                        ##Parse /etc/passwd for users
users=[]
fp=open(dir2+'/etc/passwd', 'r')
for line in fp:
    line=line.strip()
    fields=line.split(":")
    shell[fields[0]]=fields[-1]
fp.close()
for user in shell.keys():
    if shell[user]=='/bin/bash':
       users.append(user)

print "\n###### Users ######"
for user in users:
    print user

if iput.l:
    try:                            ##Try to view lastlog thru /var/log/wtmp
        command = ['last', '-f', dir1+'/var/log/wtmp']
        p=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logs, err=p.communicate()
        print "\n####### Authentication Logs #######"
        print logs
    
    except:
        print err
        print out
        print "An error occured while searching for login info"

if iput.f:
    if os.path.isfile(iput.scalp) == False:         ##If conf does not exist
        print "Error: Scalpel conf not found"
        exit()

#    try:
         
#    except:
        
if not iput.m: 
    try:                            ##Unmount and delete temp directories
        command = ['umount', dir1]
        p=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        command = ['umount', dir2]
        p=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        command = ['rm', '-r', dir1, dir2]
        p=subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print "Images have been unmounted and tmp mount points removed"
    except:
        print err
        print out
        print "Auto unmount and delete has failed, you may need to manually handle directories %s and %s" % (dir1, dir2)

print "Analysis Complete!"
