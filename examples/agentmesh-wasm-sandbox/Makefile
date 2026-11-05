SHELL := /bin/bash

.PHONY: run test clean

run:
	./run.sh

test:
	./run.sh
	cd ../.. && cargo test --test agentmesh_integration_tests

clean:
	rm -rf .run
