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

## Description

If the Mahalanobis Distance of frequency of ASCII characters is less than `threshold`, then payload is nominal.

From the original paper "Anomalous Payload-Based Network Intrusion Detection":
```
"The smoothing factor α reflects the statistical confidence of the sampled training
data. The larger the value of α , the less the confidence the samples are truly
representative of the actual distribution, and thus the byte distribution can be
more variable. Over time, as more samples are observed in training, α may be
decremented automatically."
```
