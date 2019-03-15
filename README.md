# PAYL
Models PCAP data using PAYL

## Requirements
  * Debian 9 64-bit

## Install dependencies
```
$ sudo ./setup.sh
```

## Usage
```
# Configure settings
$ vi config/payl_http.cfg
$ vi config/payl_dns.cfg

# Run PAYL
$ python payl.py config/payl_http.cfg
$ python payl.py config/payl_dns.cfg
```
