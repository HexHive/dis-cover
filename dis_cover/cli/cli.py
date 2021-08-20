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
        type=str,
        default="",
        help="Output classes in the pickle format into PICKLE.",
    )
    argp.add_argument(
        "-o",
        "--output-file",
        type=str,
        default="./reconstructed",
        help='File where the reconstructed binary should be written (default "./reconstructed")',
    )
    argp.add_argument(
        "-l",
        "--list-classes",
        action="store_true",
        default="",
        help="List the classes found in the binary",
    )
    argp.add_argument(
        "-g",
        "--graph",
        type=str,
        default="",
        help="Place a .dot file (used to create a Graphviz graph) into GRAPH.",
    )
    arguments = argp.parse_args()

    # We run the analysis
    analysis = analyse(arguments.file)

    # Creating a pickle file for later analysis of the classes and inheritance
    if arguments.pickle:
        pickle_file = open(arguments.pickle, "wb")
        pickle_file.write(pickle.dumps(analysis.classes))
        pickle_file.close()

    # Creating a .dot file for graphs
    if arguments.graph:
        gv_file = open(arguments.graph, "w")
        gv_file.write("digraph G {\n")
        gv_file.write("  node [shape=record];\n")
        for c in analysis.classes:
            # We ommit the classes that have no inheritance
            for p in c.inherits_from:
                gv_file.write('  "%s" -> "%s";\n' % (p, c.name))
        gv_file.write("}")
        gv_file.close()

    if arguments.list_classes:
        print(analysis)
    else:
        print(
            "🔎  Analysis has found %d classes in %s"
            % (len(analysis.get_classes()), arguments.file)
        )

    # Now we can start the reconstruction, stripping and combining of the binaries
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
    print("🪢   Combining reconstructed and stripped ELFs to %s" % arguments.output_file)
    unstrip = subprocess.run(
        [
            "eu-unstrip",
            stripped_file_path,
            reconstructed_file_path,
            "-o",
            arguments.output_file,
        ]
    )

    # We add a small helper message if the user created a .dot file
    if arguments.graph:
        print(
            "📊  If you would like to create a Graphviz graph, install the graphviz package and run:"
        )
        print("      $ dot -Tsvg %s -o graph.svg" % arguments.graph)


# Check if command exists on the system
def check_for_command(command):
    c = subprocess.run("command -v " + command, shell=True, capture_output=True)
    if c.returncode == 0:
        return 1
    else:
        print(command + " is needed to continue with the process")
        return 0
