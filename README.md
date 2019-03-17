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
# Extract features from pcaps to a text file
# Filter by samples.txt (filenames contained in pcap/ folder)
$ python preprocess.py pcap/ samples.txt features.txt

# Configure settings
# Examples can be found under config/
$ vi payl.cfg

# Run PAYL
$ python payl.py payl.cfg

# Evaluate
$ python evaluation.py model.pkl features.txt smoothing_factor threshold
```
