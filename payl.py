import sys
import os
import numpy as np
import random
import configparser
import cPickle as pkl

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
    feature_fn = str(config['general']['feature'])
    model_fn = str(config['general']['model'])

    protocol = str(config['payl']['type'])
    smoothing_factor = float(config['payl']['smoothing_factor'])
    threshold = float(config['payl']['threshold'])

    # If model already exists, quit
    if os.path.exists(model_fn):
        sys.stderr.write(('Error. Model file "{0}" already exists.\n'.format(model_fn)))
        sys.exit(1)

    # Check protocol parameter
    if protocol not in ['HTTP','DNS']:
        sys.stderr.write('Error. "{0}" is an invalid protocol.\n'.format(protocol))
        sys.exit(1)

    print 'Reading features'

    # Read in features
    payload = list()
    with open(feature_fn,'r') as fr:
        for line in fr:
            line = line.strip('\n')
            payload.append(line)

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

    # Train model
    model,train_lengths,min_length = analysis.train_and_test(train, test, smoothing_factor, threshold)

    print 'Saving model'

    # Store model
    with open(model_fn,'wb') as fw:
        pkl.dump(model,fw)
        pkl.dump(train_lengths,fw)
        pkl.dump(min_length,fw)

if __name__ == '__main__':
    _main()
