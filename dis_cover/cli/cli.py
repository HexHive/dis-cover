import sys
import argparse
import pickle
import subprocess
from ..analysis import analyse
from ..scenarios import run_scenarios
from ..reconstruction import reconstruct


def main():
    argp = argparse.ArgumentParser(
        description="Disasemble binaries and recover as much info as possible"
    )
    argp.add_argument("file", type=str, help="File to dis-cover")
    argp.add_argument(
        "-d",
        "--output-directory",
        type=str,
        default="/tmp",
        help="Directory where the temporary files are written (default \"/tmp\")",
    )
    argp.add_argument(
        "-p",
        "--pickle",
        action="store_true",
        default=False,
        help="Output info in the pickle format (used with --bin)",
    )
    argp.add_argument(
        "-o",
        "--output-file",
        type=str,
        default="./reconstructed",
        help="File where the output should be written (used with --bin) (default \"./reconstructed\")",
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
            reconstruction = reconstruct(analysis)
            print("Writing to %s" % arguments.file + "_reconstructed")
            file_name = arguments.file.split("/")[-1]
            reconstructed_file_path = arguments.output_directory + "/" + file_name + "_reconstructed"
            reconstructed_file = open(reconstructed_file_path, "wb")
            reconstructed_file.write(reconstruction)
            reconstructed_file.close()
            if not check_for_command("objcopy"):
                return
            print("Stripping original file")
            stripped_file_path = arguments.output_directory + "/" + file_name + "_stripped"
            strip = subprocess.run(
                ["objcopy", "--strip-all", arguments.file, stripped_file_path]
            )
            if not check_for_command("eu-unstrip"):
                return
            print("Combining reconstructed and stripped files")
            unstrip = subprocess.run(
                [
                    "eu-unstrip",
                    stripped_file_path,
                    reconstructed_file_path,
                    "-o",
                    arguments.output_file,
                ]
            )

# Check if command exists on the system
def check_for_command(command):
    c = subprocess.run("command -v " + command, shell=True, capture_output=True)
    if c.returncode == 0:
        return 1
    else:
        print(command + " is needed to continue with the process")
        return 0
