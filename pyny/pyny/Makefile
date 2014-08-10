#
# Makefile
# Copyright (C) 2006 Pyny Project.
#
# $Id: $
#

PREFIX = /usr/local

all:
	python setup.py build

install:
	python setup.py install --prefix=$(PREFIX)

exe:
	python setup-win.py py2exe

clean:
	rm -Rf build dist root
	rm -Rf cache log run
	find . -name "*.py[co]" | xargs rm -f

distclean: clean
	find . -name "*~" -o -name "#*" -o -name ".#*" | xargs rm -f
