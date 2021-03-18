.PHONY=build
build:
	docker build -t dis-cover \
	--build-arg USER_ID=$(shell id -u) \
	--build-arg GROUP_ID=$(shell id -g) .

.PHONY=shell
shell:
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover bash

.PHONY=simple_inheritance
simple_inheritance:
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover dis-cover -c case_studies/simple_inheritance.cpp -o case_studies/outputs
