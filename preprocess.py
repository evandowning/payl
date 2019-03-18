import sys
import os
import cPickle as pkl

import read_pcap

def usage():
    sys.stderr.write('usage: python preprocess.py pcap/ nominal_samples.txt features.pkl\n)'
    sys.exit(2)

def _main():
    if len(sys.argv) != 4:
        usage()

    folder = sys.argv[1]
    sample_fn = sys.argv[2]
    feature_fn = sys.argv[3]

    # Error if feature folder already exists
    if os.path.exists(feature_fn):
        sys.stderr.write('Error. Feature file "{0}" already exists.\n'.format(feature_fn))
        sys.exit(1)

    # Get samples
    sample = list()
    with open(sample_fn,'r') as fr:
        for line in fr:
            line = line.strip('\n')
            fn,label = line.split('\t')
            sample.append((os.path.join(folder,fn),label))

    # Extract payloads of all pcap data
    payload = read_pcap.getPayloadStrings(sample)

    # Store features
    with open(feature_fn,'wb') as fw:
        # Write out number of payloads
        num = len(payload)
        pkl.dump(num,fw)

        # Write out each payload
        for p,l in payload:
            pkl.dump((p,l),fw)

if __name__ == '__main__':
    _main()
