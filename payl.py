import sys
import os
import numpy as np
import random
import configparser

import read_pcap
import analysis

def usage():
    print 'usage: python payl.py payl.cfg'
    sys.exit(2)

def _main():
    if len(sys.argv) != 2:
        usage()

    configFN = sys.argv[1]

    # Read config file
    config = configparser.ConfigParser()
    config.read(configFN)

    # Parse parameters
    folder = str(config['general']['folder'])
    sample_fn = str(config['general']['samples'])

    protocol = str(config['payl']['type'])
    smoothing_lower = float(config['payl']['smoothing_lower'])
    smoothing_upper = float(config['payl']['smoothing_upper'])
    threshold_lower = float(config['payl']['threshold_lower'])
    threshold_upper = float(config['payl']['threshold_upper'])

    # Check protocol parameter
    if protocol not in ['HTTP','DNS']:
        sys.stderr.write('Error. {0} is an invalid protocol.\n'.format(protocol))
        sys.exit(1)

    # Get samples
    sample = list()
    with open(sample_fn,'r') as fr:
        for line in fr:
            line = line.strip('\n')
            sample.append(os.path.join(folder,line))

    # Extract payloads of all pcap data
    payload = read_pcap.getPayloadStrings(sample)

    # Shuffle and split payloads into training/testing sets
    random.shuffle(payload)
    thresh = int(len(payload)*0.9)
    train = payload[:thresh]
    test = payload[thresh:]

    # HTTP training set needs at least one min and one max length sample
    if protocol == 'HTTP':
        min_train = min(train,key=len)
        min_test = min(test,key=len)

        if len(min_test) < len(min_train):
            train.append(min_test)
            test.remove(min_test)

        max_train = max(train,key=len)
        max_test = max(test,key=len)

        if len(max_test) > len(max_train):
            train.append(max_test)
            test.remove(max_test)

    # Loop over parameter ranges to find best parameters
    for sf in np.arange(smoothing_lower, smoothing_upper, 0.1):
        for thresh in np.arange(threshold_lower, threshold_upper, 50):
            print 'Smoothing Factor: {0}'.format(sf)
            print 'Threshold for Mahalanobis Distance: {0}'.format(thresh)
            analysis.train_and_test(train, test, sf, thresh)
            print '---------------------------------------------'

if __name__ == '__main__':
    _main()
