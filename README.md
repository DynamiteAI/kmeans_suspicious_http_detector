# Detect and Group Suspicious HTTP Activity

This detector attempts to identify potentially suspicious HTTP traffic, and then cluster detections into related groups based on common behaviors.

## Algorithms

- #### Initial Filter Heuristic - First pass at filtering out non-suspicious activity based on HOST.
    - Shannon Entropy - Identify how random a HOST is
    - Alexa Top 500k - Identify how common a HOST is
    - Public/Private IP checks - Determine whether or not a client is calling an external IP w/o DNS lookup first

- #### Transformations - Vectorization/Normalization
  - One-hot encoding for categorical fields (string)
  - Normalization accross numeric fields
- #### Clustering - Finding optimal K clusters and Grouping
  - Silhouette Score - measure of how similar an object is to its own cluster (cohesion) compared to other clusters (separation). The silhouette ranges from -1 to 1, where a high value indicates that the object is well matched to its own cluster and poorly matched to neighboring clusters. This score is used to determine the optimal number of clusters.

  - K-Means Clustering - A method of vector quantization, originally from signal processing, that aims to partition n observations into k clusters in which each observation belongs to the cluster with the nearest mean (cluster centers or cluster centroid), serving as a prototype of the cluster.

## Proof-of-concept
[Detect_Suspicious_HTTP](notebooks/Detect-Suspicious-HTTP-Transactions.ipynb)
