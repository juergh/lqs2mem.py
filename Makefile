all: pep8 pyflakes pylint

pep8:
	pep8 --ignore=E221 lqs2mem.py

pyflakes:
	pyflakes lqs2mem.py

pylint:
	pylint --disable=C0103,C0111,C0326,R0911,R0912,R0914,W0603 \
	    --reports=n lqs2mem.py
