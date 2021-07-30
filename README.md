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

### Command-line

You can install dis-cover by running `pip install dis-cover`.

Here are the CLI options :

```
usage: dis-cover [-h] [-d OUTPUT_DIRECTORY] [-p] [-o OUTPUT_FILE] [-l] file

Disasemble binaries and recover as much info as possible

positional arguments:
  file                  ELF file to dis-cover

optional arguments:
  -h, --help            show this help message and exit
  -d OUTPUT_DIRECTORY, --output-directory OUTPUT_DIRECTORY
                        Directory where the temporary files are written (default "/tmp")
  -p, --pickle          Output info in the pickle format
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        File where the output should be written (default "./reconstructed")
  -l, --list-classes    List the classes found in the binary

```

## Still TODO

- Verify objcopy and eu-unstrip outputs (priority: medium)
- Add better error handling and more helpful messages (priority: medium)
- Set NOBIT flag in the section headers (priority: low)
- Remodel output to be more understandable (priority: low)
- Find a way to compute the size of the classes (priority: low)
