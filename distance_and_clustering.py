import numpy as np
import scipy.spatial.distance as dist
import math

'''
averaged_feature_vector : 256*2 array representing <mean,variance> pairs for each of the 256 ASCII characters
freq : 256*1 array representing the frequencies of each of the 256 ASCII characters
sf : single scalar value 
'''
def mahalanobis_distance(averaged_feature_vector, freq, sf):
    if sf == 0:
        raise Exception('Smoothing factor cannot be zero')

    dist = 0

    # For each ASCII character
    for n in range(0,256):
        xi = averaged_feature_vector[n][0]
        yi = freq[n]
        sigi = averaged_feature_vector[n][1]
        dist += (abs(xi-yi)/(sigi+sf))

    return dist
