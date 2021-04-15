import sys
import argparse
import pickle
from ..analysis import analyse
from ..scenarios import run_scenarios


def main():
    argp = argparse.ArgumentParser(
        description="Disasemble binaries and recover as much info as possible"
    )
    argp.add_argument("file", type=str, help="File to dis-cover")
    argp.add_argument(
        "-o",
        "--output-directory",
        type=str,
        default="/tmp",
        help="Directory where the temporary files are written",
    )
    argp.add_argument(
        "-p",
        "--pickle",
        action="store_true",
        default=False,
        help="Output info in the pickle format (used with --bin)",
    )
    # TODO Add dwarf output file
    group = argp.add_mutually_exclusive_group()
    group.add_argument(
        "-b",
        "--bin",
        action="store_true",
        default=True,
        help="Extract info from a binary file (default)",
    )
    group.add_argument(
        "-c",
        "--cpp",
        action="store_true",
        help="Compile C++ file under multiple scenarios and extract info from the given outputs",
    )
    arguments = argp.parse_args()

    if arguments.cpp:
        run_scenarios(arguments.file, arguments.output_directory)
    # It's important to check this last, as it defaults to True
    elif arguments.bin:
        analysis = analyse(arguments.file)
        if arguments.pickle:
            sys.stdout.buffer.write(pickle.dumps(analysis.classes))
        else:
            print(analysis)
