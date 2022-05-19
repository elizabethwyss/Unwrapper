# Shrinkwrapped Clones

This repository contains data and source code related to our work "What the Fork? Finding Hidden Code Clones in npm". In Proceedings of ICSE'22

## Data

6kPkgSample.txt - contains the subsample of 6,000 npm packages used to quantify total clones across the npm registry

6kPkgSampleClones.txt - contains the clones detected within the subsample of 6,000 npm packages used to quantify total clones across the npm registry

38PopularClones.txt - contains the 38 popular clone packages used to tune our d-score threshold

NameSimilarCloneCandidates.txt - contains the set of all npm package pairs such that one package's name is a substring of the other's name. This sample of packages was used to find name similar clones across npm

NameSimilarCloseClones.txt - contains close clones that exhibit name similarity

NameSimilarIdenticalClones.txt - contains identical clones that exhibit name similarity

popularPackages.csv - contains metadata related to the ~20,000 most popular npm packages. This data was utilized to discover the shrinkwrapped clone phenomena.

## Src

cloneDetector.py - detects clones using our d-score heuristic

CloneDetectorFilter.py - applies postfiltering to the output of the clone detector to filter out edge cases that are not clones

generatePrefilterDictionary.py - builds the dictionary file needed by the prefilter

getPkg.py - helper code used to fetch packages from our offline mirror of the npm package repository. To run other programs in this directory, you must supply your own implementation of getPkg.py that provides the functionality of this file relative to your npm storage solution.

prefilter.py - detects clone plausibility using our file tree similarity heuristics