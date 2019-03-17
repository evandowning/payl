import sys
import os

import read_pcap

def usage():
    print 'usage: python preprocess.py pcap/ samples.txt features.txt'
    sys.exit(2)

def _main():
    if len(sys.argv) != 4:
        usage()

    folder = sys.argv[1]
    sample_fn = sys.argv[2]
    feature_fn = sys.argv[3]

    # Error if feature folder already exists
    if os.path.exists(feature_fn):
        sys.stderr.write(('Error. Feature file "{0}" already exists.\n'.format(feature_fn)))
        sys.exit(1)

    # Get samples
    sample = list()
    with open(sample_fn,'r') as fr:
        for line in fr:
            line = line.strip('\n')
            sample.append(os.path.join(folder,line))

    # Extract payloads of all pcap data
    payload = read_pcap.getPayloadStrings(sample)

    # Store features
    with open(feature_fn,'w') as fw:
        for p in payload:
            # Replace Windows newlines for consistency
            p = p.replace('\r\n','\n')
            p = p.strip('\n')

            # Make sure payload is > 0
            if len(p) > 0:
                fw.write('{0}\n'.format(p))

if __name__ == '__main__':
    _main()
