import os
import sys
import subprocess
import time
import getPkg

inFile = open('PrefilterDictionary.txt')
lines = inFile.readlines()

dict = {}

dictSize = 0

print('loading dictionary...')
start = time.time()

# Generate Dictionary
for line in lines:

  dictSize += 1

  pkg = line.split()[0]
  version = ''

  if pkg[0] == '@':
    version = pkg[1:].split('@')[1]
    pkg = '@' + pkg[1:].split('@')[0]
  else:
    version = pkg.split('@')[1]
    pkg = pkg.split('@')[0]

  hashes = ''
  if len(line.split()) >= 2:
    hashes = line.split()[1]

  fileTree = []
  for h in hashes.split(','):
    if h == '~~~noFiles~~~' or h == '':
      break
    fileTree.append(int(h, base=16))

  if pkg in dict:
    dict[pkg][version] = fileTree
  else:
    pkgVersionDict = {}
    dict[pkg] = pkgVersionDict
    dict[pkg][version] = fileTree

end = time.time()
print('dictionary loaded in', (end - start), 'seconds')

answer = ''
while answer != 'quit':
  answer = input('enter pkg name: ')
  if answer not in dict:
    print('package not found')
    continue
  else:
    print('package is found!')

  version = input('enter package version: ')
  if version not in dict[answer]:
    print('version not found')
    continue

  answer2 = input('enter similarity threshold: ')
  threshold = float(answer2)

  answer3 = input('enter maximum difference in file tree size: ')
  maxSizeDiff = int(answer3)

  clone = answer
  cloneHashes = set(dict[clone][version])

  positives = 0

  print('iterating over dictionary')
  start = time.time()

  for pkg, versionDict in dict.items():
    bestRatio = 0
    bestVersion = ''
    for version, hashes in versionDict.items():
      sharedHashes = cloneHashes.intersection(hashes)
      ratio = len(sharedHashes) / len(cloneHashes)

      sizeDiff = abs(len(cloneHashes) - len(hashes))

      if ratio >= threshold and sizeDiff <= maxSizeDiff and ratio >= bestRatio:
        bestRatio = ratio
        bestVersion = version

    if bestVersion != '':
      positives += 1
      print(pkg, bestVersion, bestRatio)
  
  end = time.time()
  print('finished iterating over dictionary in', (end - start), 'seconds')
  print('total positives detected:', positives)