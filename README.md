debrepohelper
=============

A script to help you setup and manage deb repo.

### Setting up a repo
```debhelper.py setup_repo --help```

Setup a simple, signed apt repository.

* Create debrepo user. 
* Create gpg key for signing the repo. 
* Create the repo directory. 
* Create the public key file for client to import.


### Updating a repo
```debhelper.py update_repo --help```

Update the repo so that the newly added deb files are incorporated.

It does the equivalent of:
* cd /var/data/debrepo/
* apt-ftparchive packages . > Packages
* gzip -c Packages > Packages.gz
* apt-ftparchive release . > Release
* gpg --yes -abs -u `cat keyname` -o Release.gpg Release


### TODO
* write this file
* tests
* lint
