import sys
import os
import cPickle as pkl

import analysis
import distance_and_clustering as dc

def usage():
    print 'usage: python evaluation.py model.pkl features.pkl smoothing_factor threshold'
    sys.exit(2)

def _main():
    if len(sys.argv) != 5:
        usage()

    model_fn = sys.argv[1]
    feature_fn = sys.argv[2]
    smoothing_factor = float(sys.argv[3])
    threshold = float(sys.argv[4])

    print 'Reading model'

    # Read model
    model = None
    train_lengths = None
    min_length = None
    with open(model_fn,'rb') as fr:
        model = pkl.load(fr)
        train_lengths = pkl.load(fr)
        min_length = pkl.load(fr)

    print 'Reading features'

    # Read in features
    payload = list()
    with open(feature_fn,'r') as fr:
        n = pkl.load(fr)

        for i in range(n):
            payload.append(pkl.load(fr))

    TP = 0
    FP = 0
    TN = 0
    FN = 0

    print 'Testing model'

    # Test model on features
    for p,l in payload:
        mahabs_distance = sys.maxint

        # Get frequency of payload
        freq = analysis.get_freq(p)

        # If we've stored this length of payload before, retrieve the feature vector
        # and calculate the Mahalanobis Distance
        if len(p) in train_lengths:
            averaged_feature_vector = (model[min_length-len(p)])
            mahabs_distance = dc.mahalanobis_distance(averaged_feature_vector, freq, smoothing_factor)

        # Compare the distance to the threshold
        if (mahabs_distance <= threshold) and (l == '0'):
            TP += 1 # it's nominal and is classified as nominal
        elif (mahabs_distance <= threshold) and (l == '1'):
            FN += 1 # it's anomalous, but is classified as nominal
        elif (mahabs_distance > threshold) and (l == '0'):
            FP += 1 # it's nominal, but is classified as anomalous
        elif (mahabs_distance > threshold) and (l == '1'):
            TN += 1 # it's anomalous and is classified as anomalous

    print 'Total Number of samples: {0}'.format(len(payload))
    print 'TPs: {0}    FPs: {1}    TN: {2}    FN: {3}'.format(TP,FP,TN,FN)
    print 'Percentage of True positives: {0}/{1} = {2} %'.format(TP,len(payload),str((TP/float(len(payload)))*100.0))
    print 'Percentage of False positives: {0}/{1} = {2} %'.format(FP,len(payload),str((FP/float(len(payload)))*100.0))
    print 'Percentage of True negatives: {0}/{1} = {2} %'.format(TN,len(payload),str((TN/float(len(payload)))*100.0))
    print 'Percentage of False negatives: {0}/{1} = {2} %'.format(FN,len(payload),str((FN/float(len(payload)))*100.0))

if __name__ == '__main__':
    _main()
