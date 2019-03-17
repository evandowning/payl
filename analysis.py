import sys
import os
import numpy as np

import distance_and_clustering as dc
import read_pcap as dpr

# Calculates frequency of ASCII characters in string
def get_freq(s):
    rv = [0]*256
    for c in s:
        rv[ord(c)] += 1
    return rv

# Trains and tests clustering
def train_and_test(train, test, sf, thresh):
    # Dictionary keyed on payload lengths
    train_length = dict()

    # Store payloads into dictionary
    for payload in train:
        l = len(payload)

        if l not in train_length:
            train_length[l] = list()

        train_length[l].append(payload)

    # Get min and max length
    max_length = max(train_length.keys())
    min_length = min(train_length.keys())

    # Create feature vector to store values
    feature_vector = list()
    for i in range(1, max_length-min_length+2):
        mean = [0]*256
        stddev = [0]*256
        feature_vector.append(np.vstack((mean,stddev)).T)

    print 'Training Model'

    # For each length of payload, calculate the frequency of ASCII characters
    for key in sorted(train_length.keys()):

        # Create frequency array to store values
        freq = [[0]*256]*(len(train_length[key]))

        # Calculate frequency of ASCII characters
        for e,payload in enumerate(train_length[key]):
            freq[e] = get_freq(payload)

        # Store mean and std dev in feature vector for this length payload
        stddev = np.std(freq,axis=0)
        mean = np.mean(freq, axis=0)
        feature_vector[min_length-key] = np.vstack((mean,stddev)).T

    print 'Testing Model'

    TP = 0
    FN = 0

    # Run testing
    for payload in test:
        mahabs_distance = sys.maxint

        # Get frequency of payload
        freq = get_freq(payload)

        # If we've stored this length of payload before, retrieve the feature vector
        # and calculate the Mahalanobis Distance
        if len(payload) in train_length.keys():
            averaged_feature_vector = (feature_vector[min_length-len(payload)])
            mahabs_distance = dc.mahalanobis_distance(averaged_feature_vector, freq, sf)

        # Compare the distance to the threshold
        if mahabs_distance <= thresh:
            TP += 1
        else:
            FN += 1

    print 'Total Number of testing samples: {0}'.format(len(test))
    print 'TPs: {0}    FNs: {1}'.format(TP,FN)
    print 'Percentage of True positives: {0}/{1} = {2} %'.format(TP,len(test),str((TP/float(len(test)))*100.0))
    print 'Percentage of False negatives: {0}/{1} = {2} %'.format(FN,len(test),str((FN/float(len(test)))*100.0))

    # Return model
    return feature_vector,train_length.keys(),min_length
