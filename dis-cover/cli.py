import argparse


def main():
    argp = argparse.ArgumentParser(
        description="Disasemble binaries and recover as much info as possible"
    )
    argp.add_argument("file", type=str, help="Binary file to extract info from")
    arguments = argp.parse_args()
    print("Disassembling %s" % arguments.file)
