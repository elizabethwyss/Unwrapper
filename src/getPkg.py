import os
import subprocess
import json

#REPLACE THE USERNAME BELOW WITH YOUR OWN!!!
username = ''

pkgDir = '/home/npm-analysis/packages'
ratarmount = '/users/' + username + '/.local/bin/ratarmount'
ratarmountTmp = '/users/' + username + '/.ratarmount'
tmp = '/tmp/npm-checksum-analysis'

def getPkgMetadata(pkg):
  if os.path.exists(os.path.join('/home/npm-analysis/packages', pkg, 'metadata.json')):
    with open(os.path.join('/home/npm-analysis/packages', pkg, 'metadata.json')) as file:
      try:
        return json.load(file)
      except:
        return None
  return None

def getPkgVersions(pkg):
  pkgVersions = []
  if os.path.exists(os.path.join(pkgDir, pkg)):
    with os.scandir(os.path.join(pkgDir, pkg)) as it:
      for file in it:
        if file.name != 'metadata.json':
          pkgVersions.append(file.name[:-4])
  return sorted(pkgVersions)

def loadPkgVersion(pkg, version):
  if not os.path.exists(os.path.join(tmp, pkg + version)):
    subprocess.run(['mkdir', os.path.join(tmp, pkg + version)])
  subprocess.run(['python3', ratarmount, '-c', '--index-folders', '/tmp', os.path.join(pkgDir, pkg, version + '.tgz'), os.path.join(tmp, pkg + version)])

  subdirs = os.listdir(os.path.join(tmp, pkg + version))
  if len(subdirs) <= 0:
    with open('missingPackageVersions.txt', 'a') as missingPackageFile:
      missingPackageFile.write(pkg + ' ' + version + '\n')

def cleanupPkgVersion(pkg, version):
  if os.path.exists(os.path.join(tmp, pkg + version)):
    subprocess.run(['fusermount', '-u', os.path.join(tmp, pkg + version)])
    subprocess.run(['rm', '-rf', os.path.join(tmp, pkg + version)])
  if os.path.exists(os.path.join(ratarmountTmp, tmp.replace('/', '_') + '_' + pkg + '_' + version + '.tgz.index.sqlite')):
    subprocess.run(['rm', os.path.join(ratarmountTmp, tmp.replace('/', '_') + '_' + pkg + '_' + version + '.tgz.index.sqlite')])
  if os.path.exists('/tmp/_home_npm-analysis_packages_' + pkg + '_' + version + '.tgz.index.sqlite'):
    subprocess.run(['rm', '-f', '/tmp/_home_npm-analysis_packages_' + pkg + '_' + version + '.tgz.index.sqlite'])

if __name__ == '__main__':
  print(getPkgVersions('test101'))
  loadPkgVersion('test101', '0.0.1')
  subprocess.run(['cat', os.path.join(tmp, 'test1010.0.1', 'package', 'package.json')])
  cleanupPkgVersion('test101', '0.0.1')
