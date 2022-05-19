import os
import sys
import subprocess
import hashlib
import multiprocessing as mp
import time
from glob import glob
import getPkg

def worker(pkg, lock):
  versions = getPkg.getPkgVersions(pkg)
  if len(versions) <= 0:
    return
  for version in versions:
    getPkg.loadPkgVersion(pkg, version)
    subdirs = os.listdir(os.path.join('/tmp/npm-checksum-analysis', pkg + version))
    if len(subdirs) <= 0:
      getPkg.cleanupPkgVersion(pkg, version)
      continue
    subdir = subdirs[0]

    hashes = []
    paths = glob('/tmp/npm-checksum-analysis/' + pkg + version + '/**/*', recursive=True)

    isTrivial = True

    for path in paths:
      if os.path.isfile(path):

        if isTrivial:
          if path.endswith('.js') or path.endswith('.ts') or path.endswith('.css'):
            isTrivial = False

        prefix = '/tmp/npm-checksum-analysis/' + pkg + version + '/' + subdir + '/'
        h = int(hashlib.sha256(path[len(prefix):].encode('utf-8')).hexdigest(), 16) % 2**32
        hashes.append(hex(h))

    if isTrivial or len(hashes) <= 0:
      getPkg.cleanupPkgVersion(pkg, version)
      continue

    hashes = sorted(hashes)

    outputStr = pkg + '@' + version + ' '
    firstCommaSkipped = False
    for h in hashes:
      if not firstCommaSkipped:
        outputStr += h[2:]
        firstCommaSkipped = True
      else:
        outputStr += ',' + h[2:]
    outputStr += '\n'

    getPkg.cleanupPkgVersion(pkg, version)

    lock.acquire()
    outFile = open('prefilterCompleteDictionary.txt', 'a')
    outFile.write(outputStr)
    outFile.close()
    lock.release()


  
def startWorkers():
  maxWorkers = 30
  lock = mp.Lock()

  pkgsAnalyzed = 0
  for line in open('packageList.txt'):
    pkg = line.rstrip('\n')
    pkgsAnalyzed += 1
    print('\n', pkgsAnalyzed, '\n')

    newProcess = mp.Process(target=worker, args=[pkg, lock])
    newProcess.start()

    while len(mp.active_children()) >= maxWorkers:
      time.sleep(1)
  
  # try to wait for all workers to finish
  while len(mp.active_children()) > 0:
    time.sleep(1)

if __name__ == '__main__':
  startWorkers()
