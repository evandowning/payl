'''
    Wrapper script for OMSCS CS 6262 Project 5
    run as : python wrapper.py

'''
import read_pcap as dpr
import random as rn
import sys
import os
import analysis
import configparser

def usage():
    print 'usage: python wrapper.py payl.cfg data/'
    print '------'
    print 'OR'
    print '------'
    print 'usage: python wrapper.py payl.cfg training/ testing/'
    sys.exit(2)

def _main():
    if len(sys.argv) != 3 and len(sys.argv) != 4:
        usage()

    configFN = sys.argv[1]
    trainingFolder = sys.argv[2]

    if len(sys.argv) == 4:
        testingFolder = sys.argv[3]
    else:
        testingFolder = ''

    # Read config file
    config = configparser.ConfigParser()
    config.read(configFN)

    # Parse parameters
    training_protocol = str(config['payl']['type'])
    smoothing_factor_lower = int(config['payl']['smoothing_lower'])
    smoothing_factor_upper = int(config['payl']['smoothing_upper'])
    threshold_for_mahalanobis_lower = int(config['payl']['threshold_lower'])
    threshold_for_mahalanobis_upper = int(config['payl']['threshold_upper'])

    print "Working with protocol: " + training_protocol + " : in training data."

    if testingFolder == '':
        print '\tTraining/testing on {0}'.format(trainingFolder)
    else:
        print '\tTraining on {0}\t Testing on {1}'.format(trainingFolder,testingFolder)

    payloads = dpr.getPayloadStrings(trainingFolder)
    # shuffle the data to randomly pick samples
    rn.shuffle(payloads)

    #Case: DNS traffic. 
    split_ratio = 0.75
    split_index = int(len(payloads)*split_ratio)
    training = payloads[0:split_index+1]
    test = payloads[split_index+1:len(payloads)]

    if training_protocol == 'HTTP':
        min_length = 0 
        max_length = 0
    elif training_protocol == 'DNS':
        min_length = 0 
        max_length = 1
        split_ratio = 0.75
        split_index = int(len(payloads)*split_ratio)
        training = payloads[0:split_index+1]
        test = payloads[split_index+1:len(payloads)]
    else:
        print 'Error. Invalid type {0}'.format(training_protocol)
        sys.exit(1)

    while min_length == 0 and max_length == 0:    
        min_length = 0 
        max_length = 0
        # This is where we decide what the split ratio is
        split_ratio = 0.75
        split_index = int(len(payloads)*split_ratio)
        training = payloads[0:split_index+1]
        test = payloads[split_index+1:len(payloads)]

        # we need at least one min and max length samples in the training data set
        for x in training:
            if len(x) == 0:
                min_length = 1
            if len(x) == 1460:
                max_length =1
        for j in range(0,len(test)):        
            if len(test[j]) == 705:
                for i in range(0, len(training)):
                    if len(training[i]) !=0 and len(training[i]) != 1460 and len(training[i]) !=705:
                        t = training[i]
                        training[i] = test[j]
                        test[j] = t
                        i = len(training)+1                   

    # Simple sanity check
    if len(payloads) != len(test)+len(training) or split_ratio >= 1.0:
        sys.exit()
    else:
        '''
        To better understand the behaviour of the model with different parameters, we typically 
        let the parameters iterate over a range.

        Here, range(threshold_for_mahalanobis_lower, threshold_for_mahalanobis_upper+1) is the 
        range over which the mahalanobis threshold iterates. 
        Similarly, range(smoothing_factor_lower, smoothing_factor_upper+0.1) is the range over
        which the smoothing factor iterates.

        For each such combination of mahalanobis threshold and smoothing factor, the model is 
        generated with these parameters.
        '''

        if testingFolder != '':
            for test_file in os.listdir(testingFolder):
                # this loops from smoothing_factor_lower to smoothing_factor_upper in steps of 0.1
                for smoothing_factor in range(smoothing_factor_lower, smoothing_factor_upper+1):
                    for mahabs in range(threshold_for_mahalanobis_lower, threshold_for_mahalanobis_upper+1, 50):
                        print 'Smoothing Factor: '+str(smoothing_factor/10.0)
                        print 'Threshold for Mahalanobis Distance: '+str(mahabs)
                        analysis.train_and_test(training, test, os.path.join(testingFolder,test_file), smoothing_factor/10.0, mahabs, verbose = "False")
                        print '---------------------------------------------'
        else:
            # this loops from smoothing_factor_lower to smoothing_factor_upper in steps of 0.1
            for smoothing_factor in range(smoothing_factor_lower, smoothing_factor_upper+1):
                for mahabs in range(threshold_for_mahalanobis_lower, threshold_for_mahalanobis_upper+1, 50):
                    print 'Smoothing Factor: '+str(smoothing_factor/10.0)
                    print 'Threshold for Mahalanobis Distance: '+str(mahabs)
                    analysis.train_and_test(training, test, None, smoothing_factor/10.0, mahabs, verbose = "False")
                    print '---------------------------------------------'

if __name__ == '__main__':
    _main()
