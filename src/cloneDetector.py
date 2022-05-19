import os
import sys
import subprocess
import filecmp
import json
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


def generateCandidateVersions(origPkg, clonePkg):
  origVersions = getPkg.getPkgVersions(origPkg)
  cloneVersions = getPkg.getPkgVersions(clonePkg)
  cloneVersion = cloneVersions[-1]
  return cloneVersion, origVersions

def testCandidateVersions(workerID, origPkg, candidateVersions, clonePkg, cloneVersion, outFile):
  generateChecksums(workerID, clonePkg, cloneVersion)

  bestDiffScore = 1000000
  bestVersion = candidateVersions[0]
  bestOrigUnique = []
  bestCloneUnique = []
  bestDiffHashes = []

  for version in candidateVersions:
    getPkg.loadPkgVersion(origPkg, version)
    generateChecksums(workerID, origPkg, version)
    getPkg.cleanupPkgVersion(origPkg, version)

    origUnique, cloneUnique, diffHashes, diffScore = comparePackageChecksums(workerID, origPkg, version, clonePkg, cloneVersion, outFile)

    if diffScore <= bestDiffScore:
      bestDiffScore = diffScore
      bestVersion = version
      bestOrigUnique = origUnique
      bestCloneUnique = cloneUnique
      bestDiffHashes = diffHashes

  return bestVersion, bestOrigUnique, bestCloneUnique, bestDiffHashes, bestDiffScore

if __name__ == '__main__':

  origPkg = sys.argv[1]
  clonePkg = sys.argv[2]
  workerID = sys.argv[3]

  origPkg = origPkg.replace('/', '~')
  clonePkg = clonePkg.replace('/', '~')
  cloneVersion, candidateVersions = generateCandidateVersions(origPkg, clonePkg)

  getPkg.loadPkgVersion(clonePkg, cloneVersion)

  origVersion, origUnique, cloneUnique, diffHashes, diffScore = testCandidateVersions(workerID, origPkg, candidateVersions, clonePkg, cloneVersion, None)

  subprocess.run(['rm', '-rf', '/tmp/checksums' + workerID])

  if diffScore <= 11:

    fileName = 'closeClones.txt'
    if diffScore == 1:
      fileName = 'IdenticalClones.txt'

    with open(fileName, 'a') as outFile:
      outFile.write(origPkg + '@' + origVersion + ' ' + clonePkg + '@' + cloneVersion + '\n')

    getPkg.loadPkgVersion(origPkg, origVersion)

    origSubdir = os.listdir(os.path.join('/tmp/npm-checksum-analysis', origPkg + origVersion))[0]
    origDir = os.path.join('/tmp/npm-checksum-analysis', origPkg + origVersion, origSubdir)

    cloneSubdir = os.listdir(os.path.join('/tmp/npm-checksum-analysis', clonePkg + cloneVersion))[0]
    cloneDir = os.path.join('/tmp/npm-checksum-analysis', clonePkg + cloneVersion, cloneSubdir)

  getPkg.cleanupPkgVersion(origPkg, origVersion)
  getPkg.cleanupPkgVersion(clonePkg, cloneVersion)

  print(clonePkg, cloneVersion, cloneUnique)
  print(origPkg, origVersion, origUnique)
  print(diffHashes)
  print(diffScore)