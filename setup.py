from setuptools import setup
    
setup(
    name = "debhelper",
    py_modules = ["debhelper"],
    scripts = ["debhelper.py"],
    version = "0.3.0",
    license = "LGPL",
    platforms = ['POSIX'],      # debian only..
    install_requires=["baker"],
    setup_requires=["nose"],
    description = "Setup and manage deb repo easily.",
    author = "karasuyamatengu",
    author_email = "karasuyamatengu@gmail.com",
    url = "https://github.com/tengu/debhelper",
    keywords = ["debian", "package"],
    long_description = """
debrepohelper
=============

A script to help you setup and manage deb repo.

## Setting up a repo

```
debhelper.py setup_repo --help
```

Setup a simple, signed apt repository.

* Create debrepo user. 
* Create gpg key for signing the repo. 
* Create the repo directory. 
* Create the public key file for client to import.


## Updating a repo

```
debhelper.py update_repo --help
```

Update the repo so that the newly added deb files are incorporated.

It does the equivalent of:

* cd /var/data/debrepo/
* apt-ftparchive packages . > Packages
* gzip -c Packages > Packages.gz
* apt-ftparchive release . > Release
* gpg --yes -abs -u `cat keyname` -o Release.gpg Release
"""
)
