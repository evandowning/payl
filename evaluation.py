import sys
import os
import cPickle as pkl

import analysis
import distance_and_clustering as dc

def usage():
    sys.stderr.write('usage: python evaluation.py model.pkl features.pkl smoothing_factor threshold\n')
    sys.exit(2)

def _main():
    if len(sys.argv) != 5:
        usage()

    model_fn = sys.argv[1]
    feature_fn = sys.argv[2]
    smoothing_factor = float(sys.argv[3])
    threshold = float(sys.argv[4])

    sys.stdout.write('Reading model\n')

    # Read model
    model = None
    train_lengths = None
    min_length = None
    with open(model_fn,'rb') as fr:
        model = pkl.load(fr)
        train_lengths = pkl.load(fr)
        min_length = pkl.load(fr)

    sys.stdout.write('Reading features\n')

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

    total_nominal = 0
    total_anomalous = 0

    sys.stdout.write('Testing model\n')

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

        # Tally number of nominal and anomalous samples
        if l == '0':
            total_nominal += 1
        elif l == '1':
            total_anomalous += 1

        # Compare the distance to the threshold
        if (mahabs_distance <= threshold) and (l == '0'):
            TP += 1 # it's nominal and is classified as nominal
        elif (mahabs_distance > threshold) and (l == '0'):
            FP += 1 # it's nominal, but is classified as anomalous
        elif (mahabs_distance > threshold) and (l == '1'):
            TN += 1 # it's anomalous and is classified as anomalous
        elif (mahabs_distance <= threshold) and (l == '1'):
            FN += 1 # it's anomalous, but is classified as nominal

    sys.stdout.write('Total Number of samples: {0}\n'.format(len(payload)))
    sys.stdout.write('Nominal: {0}    Anomalous: {1}\n'.format(total_nominal,total_anomalous))
    sys.stdout.write('TPs: {0}    FPs: {1}    TN: {2}    FN: {3}\n'.format(TP,FP,TN,FN))
    if total_nominal > 0:
        sys.stdout.write('Percentage of True positives: {0}/{1} = {2} %\n'.format(TP,total_nominal,str((TP/float(total_nominal))*100.0)))
    if total_nominal > 0:
        sys.stdout.write('Percentage of False positives: {0}/{1} = {2} %\n'.format(FP,total_nominal,str((FP/float(total_nominal))*100.0)))
    if total_anomalous > 0:
        sys.stdout.write('Percentage of True negatives: {0}/{1} = {2} %\n'.format(TN,total_anomalous,str((TN/float(total_anomalous))*100.0)))
    if total_anomalous > 0:
        sys.stdout.write('Percentage of False negatives: {0}/{1} = {2} %\n'.format(FN,total_anomalous,str((FN/float(total_anomalous))*100.0)))

if __name__ == '__main__':
    _main()
