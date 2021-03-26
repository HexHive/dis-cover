.PHONY=build
build:
	docker build -t dis-cover \
	--build-arg USER_ID=$(shell id -u) \
	--build-arg GROUP_ID=$(shell id -g) .

.PHONY=shell
shell: build
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover bash

.PHONY=run_scenarios
run_scenarios: build
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover dis-cover -c case-studies/simple_inheritance.cpp -o case-studies/outputs
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover dis-cover -c case-studies/diamond_problem.cpp -o case-studies/outputs

.PHONY=clean
clean:
	rm case-studies/outputs/*

.PHONY=lint
lint: build
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover black .
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover clang-format -i case-studies/*.cpp
