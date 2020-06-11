
all:

#include local.mk

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

#### packaging
deb_name?=debhelper
deb_version?=0.3
deb_message?=a simple tool for managing a deb repo
deb_repo=127.0.0.1
cmd=debhelper.py
installed_cmd=/usr/local/bin/$(cmd)

$(installed_cmd): $(cmd)
	sudo install $< $@

pack: $(installed_cmd)
	ls $< \
	| debify.py pack_paths \
		$(deb_name)_$(deb_version) \
		"$(deb_message)"

publish:
	ls $(deb_name)_$(deb_version).deb | debhelper.py push $(deb_repo)
