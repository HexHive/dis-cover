# dis-cover
Disassemble binaries and recover as much info as possible

## How to use

### Run on you binary

To run this tool on your own binary, first you must install dis-cover, as well as elfutils and binutils.

```
pip install dis-cover
apt install elfutils binutils # or whatever your version of this is
```

Then, you can run it to analyze your binary, for example `/bin/gold`.

```
dis-cover /bin/gold
```

This will create a `reconstructed` elf file in your current directory. This binary will contain symbols and dwarf information describing the classes and hierarchies that dis-cover was able to find.

### Run the case studies

To run the case studies, simply `make run-scenarios`. You need to have `docker` installed.

### Command-line

You can install dis-cover by running `pip install dis-cover`.

Here are the CLI options :

```
$ dis-cover --help
usage: dis-cover [-h] [-d OUTPUT_DIRECTORY] [-p] [-o OUTPUT_FILE] [-b | -c] file

Disasemble binaries and recover as much info as possible

positional arguments:
  file                  File to dis-cover

optional arguments:
  -h, --help            show this help message and exit
  -d OUTPUT_DIRECTORY, --output-directory OUTPUT_DIRECTORY
                        Directory where the temporary files are written
  -p, --pickle          Output info in the pickle format (used with --bin)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        File where the output should be written (used with --bin)
  -b, --bin             Extract info from a binary file (default)
  -c, --cpp             Compile C++ file under multiple scenarios and extract info from the given outputs
```

## Still TODO

- Check if objcopy and eu-unstrip exist before using them (priority: medium)
- Verify objcopy and eu-unstrip outputs (priority: medium)
- Set NOBIT flag in the section headers (priority: low)
