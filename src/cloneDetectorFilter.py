import os
import sys
import subprocess
import filecmp
import json
from glob import glob
from filehash import FileHash
import getPkg

fileHasher = FileHash()

def recGenerateChecksums(inputDir, outputDir):
  with os.scandir(inputDir) as it:
    for file in it:
      if file.is_dir(follow_symlinks=False):
        newOutputDir = os.path.join(outputDir, file.name)
        newInputDir = os.path.join(inputDir, file.name)
        if not os.path.exists(newOutputDir):
          subprocess.run(['mkdir', newOutputDir])
        recGenerateChecksums(newInputDir, newOutputDir)
      elif file.is_file(follow_symlinks=False):
        with open(os.path.join(outputDir, file.name + '.sha256'), 'w') as outFile:
          outFile.write(fileHasher.hash_file(os.path.join(inputDir, file.name)))

def generateChecksums(workerID, pkg, version):
  if not os.path.exists('/tmp/checksums' + workerID):
    subprocess.run(['mkdir', '/tmp/checksums' + workerID])
  outputDir = os.path.join('/tmp/checksums' + workerID, pkg + '@' + version)
  if not os.path.exists(outputDir):
    subprocess.run(['mkdir', outputDir])

  subdirs = os.listdir(os.path.join('/tmp/npm-checksum-analysis', pkg + version))
  if len(subdirs) <= 0:
    return
  subdir = subdirs[0]

  recGenerateChecksums(os.path.join('/tmp/npm-checksum-analysis', pkg + version, subdir), outputDir)

def recComparePackageChecksums(dcmp, baseDir1, baseDir2, diffHashes, only1, only2):
  if len(dcmp.left_only) > 0:
    for name in dcmp.left_only:
      if baseDir1 == dcmp.left:
        if name[-7:] == '.sha256':
          only1.append(name[:-7])
        else:
          only1.append(name)
      else:
        if name[-7:] == '.sha256':
          only1.append(os.path.relpath(dcmp.left, baseDir1) + '/' + name[:-7])
        else:
          only1.append(os.path.relpath(dcmp.left, baseDir1) + '/' + name)
        
  if len(dcmp.right_only) > 0:
    for name in dcmp.right_only:
      if baseDir2 == dcmp.right:
        if name[-7:] == '.sha256':
          only2.append(name[:-7])
        else:
          only2.append(name)
      else:
        if name[-7:] == '.sha256':
          only2.append(os.path.relpath(dcmp.right, baseDir2) + '/' + name[:-7])
        else:
          only2.append(os.path.relpath(dcmp.right, baseDir2) + '/' + name)

  for name in dcmp.diff_files:
    if baseDir1 == dcmp.left:
      diffHashes.append(name[:-7])
    else:
      diffHashes.append(os.path.relpath(dcmp.left, baseDir1) + '/' + name[:-7])
  for sub_dcmp in dcmp.subdirs.values():
    recComparePackageChecksums(sub_dcmp, baseDir1, baseDir2, diffHashes, only1, only2)

def comparePackageChecksums(workerID, pkg1, pkg1Version, pkg2, pkg2Version, outFile):
  baseDir1 = os.path.join('/tmp/checksums' + workerID, pkg1 + '@' + pkg1Version)
  baseDir2 = os.path.join('/tmp/checksums' + workerID, pkg2 + '@' + pkg2Version)

  diffHashes = []
  only1 = []
  only2 = []

  dcmp = filecmp.dircmp(baseDir1, baseDir2)
  recComparePackageChecksums(dcmp, baseDir1, baseDir2, diffHashes, only1, only2)

  diffScore = len(diffHashes)
  
  for item in only1:
    if os.path.isdir(os.path.join(baseDir1, item)):
      diffScore += 2 * sum([len(files) for r, d, files in os.walk(os.path.join(baseDir1, item))])
    else:
      diffScore += 2

  for item in only2:
    if os.path.isdir(os.path.join(baseDir2, item)):
      diffScore += 2 * sum([len(files) for r, d, files in os.walk(os.path.join(baseDir2, item))])
    else:
      diffScore += 2

  if len(diffHashes) <= 0:
    if len(only1) <= 0 or len(only2) <= 0:
      return [], [], [], 1000000

  if outFile != None:
    outFile.write('Unique to ' + pkg1 + '@' + pkg1Version + ': ' + str(only1) + '\n')
    outFile.write('Unique to ' + pkg2 + '@' + pkg2Version + ': ' + str(only2) + '\n')
    outFile.write('Different Hashes: ' + str(diffHashes) + '\n')
    outFile.write('Difference Score: ' + str(diffScore) + '\n\n')

  return only1, only2, diffHashes, diffScore

# Main analysis starts here

inFile = open('closeClones.txt')
outFile = open('filteredCloseClones.txt', 'w')


clonesEvaluated = 0

for line in inFile:
  clonesEvaluated += 1
  if clonesEvaluated > 1000000000:
    break

  origNameVersion = line.split()[0]
  cloneNameVersion = line.split()[1]

  orig = origNameVersion.split('@')[0]
  origVersion = origNameVersion.split('@')[1]

  clone = '@' + cloneNameVersion[1:].split('@')[0]
  cloneVersion = cloneNameVersion[1:].split('@')[1]

  # Filter out packages that appear to be clones of built in modules

  builtIns = ['assert', 'buffer', 'child_process', 'cluster', 'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http', 'https', 'net', 'os', 'path', 'querystring', 'readline', 'stream', 'string_decoder', 'timers', 'tls', 'tty', 'url', 'util', 'v8', 'vm', 'zlib']
  if orig in builtIns:
    # This is likely an independent package with a scoped name matching a built in package
    print('BUILT IN MODULE FALSE POSITIVE DETECTED')
    continue

  getPkg.loadPkgVersion(orig, origVersion)
  getPkg.loadPkgVersion(clone, cloneVersion)

  # Filter out packages that only provide typescript definitions for a javascript package

  origJS = glob('/tmp/npm-checksum-analysis/' + orig + origVersion + '/*/*.js') + glob('/tmp/npm-checksum-analysis/' + orig + origVersion + '/*/*/*.js')
  origTS = glob('/tmp/npm-checksum-analysis/' + orig + origVersion + '/*/*.ts') + glob('/tmp/npm-checksum-analysis/' + orig + origVersion + '/*/*/*.ts')

  cloneJS = glob('/tmp/npm-checksum-analysis/' + clone + cloneVersion + '/*/*.js') + glob('/tmp/npm-checksum-analysis/' + clone + cloneVersion + '/*/*/*.js')
  cloneTS = glob('/tmp/npm-checksum-analysis/' + clone + cloneVersion + '/*/*.ts') + glob('/tmp/npm-checksum-analysis/' + clone + cloneVersion + '/*/*/*.ts')

  if len(origJS) > 0 and len(cloneJS) == 0 and len(cloneTS) > 0:
    # This is a type definitions package, not a clone
    getPkg.cleanupPkgVersion(orig, origVersion)
    getPkg.cleanupPkgVersion(clone, cloneVersion)
    print('TYPESCRIPT DEFINITIONS FALSE POSITIVE DETECTED')
    continue

  # Filter out small-sized packages that are independent

  generateChecksums('', orig, origVersion)
  generateChecksums('', clone, cloneVersion)
  origOnly, cloneOnly, bothDifferent, diffScore = comparePackageChecksums('', orig, origVersion, clone, cloneVersion, None)

  cloneSize = len(glob('/tmp/checksums/' + clone + '@' + cloneVersion + '/**/*.sha256', recursive=True))

  getPkg.cleanupPkgVersion(orig, origVersion)
  getPkg.cleanupPkgVersion(clone, cloneVersion)
  subprocess.run(['rm', '-rf', '/tmp/checksums'])

  print(cloneSize)
  print(diffScore)

  if cloneSize == 1 and diffScore > 1:
    print('CLONE SIZE 1 FALSE POSITIVE DETECTED')
    continue
  if cloneSize == 2 and diffScore > 2:
    print('CLONE SIZE 2 FALSE POSITIVE DETECTED')
    continue
  if cloneSize == 3 and diffScore > 4:
    print('CLONE SIZE 3 FALSE POSITIVE DETECTED')
    continue
  if cloneSize == 4 and diffScore > 6:
    print('CLONE SIZE 4 FALSE POSITIVE DETECTED')
    continue
  if cloneSize == 5 and diffScore > 8:
    print('CLONE SIZE 5 FALSE POSITIVE DETECTED')
    continue
  if cloneSize == 6 and diffScore > 10:
    print('CLONE SIZE 6 FALSE POSITIVE DETECTED')
    continue

  outFile.write(line)
