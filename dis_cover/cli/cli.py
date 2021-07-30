import sys
import argparse
import pickle
import subprocess
from ..analysis import analyse
from ..reconstruction import reconstruct


def main():
    argp = argparse.ArgumentParser(
        description="Disasemble binaries and recover as much info as possible"
    )
    argp.add_argument("file", type=str, help="ELF file to dis-cover")
    argp.add_argument(
        "-d",
        "--output-directory",
        type=str,
        default="/tmp",
        help='Directory where the temporary files are written (default "/tmp")',
    )
    argp.add_argument(
        "-p",
        "--pickle",
        action="store_true",
        default=False,
        help="Output info in the pickle format",
    )
    argp.add_argument(
        "-o",
        "--output-file",
        type=str,
        default="./reconstructed",
        help='File where the output should be written (default "./reconstructed")',
    )
    argp.add_argument(
        "-l",
        "--list-classes",
        action="store_true",
        default=False,
        help="List the classes found in the binary",
    )
    arguments = argp.parse_args()

    # We run the analysis
    analysis = analyse(arguments.file)

    if arguments.pickle:
        sys.stdout.buffer.write(pickle.dumps(analysis.classes))
    else:
        if arguments.list_classes:
            print(analysis)
        else:
            print(
                "🔎  Analysis has found %d classes in %s"
                % (len(analysis.get_classes()), arguments.file)
            )
        reconstruction = reconstruct(analysis)
        file_name = arguments.file.split("/")[-1]
        reconstructed_file_path = (
            arguments.output_directory + "/" + file_name + "_reconstructed"
        )
        print("🏗️   Writing reconstructed ELF to %s" % reconstructed_file_path)
        reconstructed_file = open(reconstructed_file_path, "wb")
        reconstructed_file.write(reconstruction)
        reconstructed_file.close()
        if not check_for_command("objcopy"):
            return
        stripped_file_path = arguments.output_directory + "/" + file_name + "_stripped"
        print("✂️   Stripping original ELF to %s" % stripped_file_path)
        strip = subprocess.run(
            ["objcopy", "--strip-all", arguments.file, stripped_file_path]
        )
        if not check_for_command("eu-unstrip"):
            return
        print(
            "🪢   Combining reconstructed and stripped ELFs to %s"
            % arguments.output_file
        )
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
