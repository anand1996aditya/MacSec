.PHONY: install test verify run lint

install:
	./install.sh

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

verify:
	./verify.sh

run:
	./run.sh

lint:
	PYTHONPATH=src python3 -m compileall -q src tests
	bash -n install.sh run.sh verify.sh
