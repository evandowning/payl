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
# samples.txt is tab-separated by a value of 0 (nominal) or 1 (anomalous)
$ python preprocess.py pcap/ samples.txt features.pkl

# Configure settings
# Examples can be found under config/
$ vi payl.cfg

# Run PAYL
$ python payl.py payl.cfg

# Evaluate
$ python evaluation.py model.pkl features.pkl smoothing_factor threshold
```
