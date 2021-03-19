from compilation import compile_under_scenario
from analysis import analyse
import subprocess

COMPILERS = [
    "clang++",
    "g++",
]

OPTIONS = [
    "-O0",
    "-O1",
    "-O2",
    "-O3",
    "-Os",
    "-fno-exceptions",
    "-fno-unwind-tables",
    "-fno-rtti",
]


def run_scenarios(source_file_name, output_directory):
    for compiler in COMPILERS:
        for option in OPTIONS:
            elf_file_name = compile_under_scenario(
                source_file_name, (compiler, option), output_directory
            )
            results = analyse(elf_file_name)
            print("\tFound \033[1m%d\033[0m vtable calls" % results)
