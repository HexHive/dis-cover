.PHONY=build
build:
	docker build -t dis-cover \
	--build-arg USER_ID=$(shell id -u) \
	--build-arg GROUP_ID=$(shell id -g) .

.PHONY=shell
shell: build
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover bash

.PHONY=simple_inheritance
simple_inheritance: build
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover dis-cover -c case-studies/simple_inheritance.cpp -o case-studies/outputs
