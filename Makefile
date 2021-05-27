.PHONY=build
build:
	docker build -t dis-cover \
		--build-arg USER_ID=$(shell id -u) \
		--build-arg GROUP_ID=$(shell id -g) .
	docker build -t dis-cover-alpine \
		--build-arg USER_ID=$(shell id -u) \
		--build-arg GROUP_ID=$(shell id -g) \
		-f Dockerfile.alpine .

.PHONY=run_scenarios
run_scenarios: build
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover bash -c "\
		pip install -e /home/dis-cover/dis-cover &&\
		find ./case_studies/ -iname '*.cpp' -exec ~/.local/bin/dis-cover -c {} -d case_studies/outputs \;"

.PHONY=run_scenarios_alpine
run_scenarios_alpine: build
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover-alpine bash -c "\
		pip install -e /home/dis-cover/dis-cover &&\
		find ./case_studies/ -iname '*.cpp' -exec ~/.local/bin/dis-cover -c {} -d case_studies/outputs \;"

.PHONY=clean
clean:
	rm -rf case_studies/outputs/* dis_cover/__pycache__ */**/__pycache__ dis_cover.egg-info build dist

.PHONY=lint
lint: build
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover black .
	docker run --rm -v "${PWD}:/home/dis-cover/dis-cover" -it dis-cover clang-format -i case_studies/*.cpp

analyze_packages:
	docker build -t dis-cover-analysis ./packages_analysis/
	docker run dis-cover-analysis > analysis.pickle
	python3 packages_analysis/process.py

jupyter-notebook:
	docker build -t dis-cover-notebook -f ./packages_analysis/Dockerfile.notebook ./packages_analysis/
	docker run -p 8888:8888 -v ${PWD}/packages_analysis:/home/jovyan/work dis-cover-notebook
