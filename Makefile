
all:

include local.mk

clean:
	rm -fr *.egg-info .eggs dist

sdist:
	python3 setup.py sdist

pypi-upload:
	python3 setup.py sdist upload


install:
	sudo install debhelper.py /usr/local/bin/

setup_repo:
	./debhelper.py setup_repo

update_repo: install
	sudo sudo --login -u debrepo /usr/local/bin/debhelper.py update_repo
