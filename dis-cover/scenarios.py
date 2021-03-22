from elftools.elf.elffile import ELFFile
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


def extract_dwarf_data(source_file_name, output_directory):
    compiled_with_dwarf = compile_under_scenario(
        source_file_name, ("clang++", "-gdwarf"), output_directory
    )
    elf_with_dwarf = ELFFile(open(compiled_with_dwarf, "rb"))
    dwarf_info = elf_with_dwarf.get_dwarf_info()


def run_scenarios(source_file_name, output_directory):

    extract_dwarf_data(source_file_name, output_directory)

    for compiler in COMPILERS:
        for option in OPTIONS:
            elf_file_name = compile_under_scenario(
                source_file_name, (compiler, option), output_directory
            )
            results = analyse(elf_file_name)
            print("\tFound \033[1m%d\033[0m vtable calls" % results.vfunc_calls)
