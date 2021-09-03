.PHONY=build
build:
	docker build -t dis-cover \
		--build-arg USER_ID=$(shell id -u) \
		--build-arg GROUP_ID=$(shell id -g) .

.PHONY=run_case_studies
run_case_studies: build
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover bash -c "\
		pip install -e /home/dis-cover/dis-cover &&\
		find ./case_studies/ -iname '*.cpp' -exec python ./case_studies/test_case_study.py {} \;"

.PHONY=clean
clean:
	rm -rf case_studies/outputs/* dis_cover/__pycache__ */**/__pycache__ dis_cover.egg-info build dist

.PHONY=lint
lint: build
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover black .
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover clang-format -i case_studies/*.cpp
