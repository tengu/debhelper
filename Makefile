
all:

include local.mk

clean:
	rm -fr *.egg-info .eggs dist

sdist:
	python3 setup.py sdist

pypi-upload:
	python3 setup.py sdist upload
