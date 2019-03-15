#!/bin/bash

uid=`id -u`

# Check user permissions
if [[ $uid -ne 0 ]]; then
    echo 'must be root'
    exit 2
fi

# Stop on any error
set -e

# Update
apt update

# Install python2.7
apt install -y python2.7
apt install -y python-tk    # https://dpkt.readthedocs.io/en/latest/
apt install -y python-scipy
apt install -y python-pip
pip install -r requirements.txt
