import sys
import subprocess
import pickle

UPDATE_COMMAND = "apt-get update"
GCC_RDEPENDENCIES_COMMAND = "apt-cache rdepends libgcc1"  # Debian
# GCC_RDEPENDENCIES_COMMAND = "apt-cache rdepends libgcc-s1" # Ubuntu
DOWNLOAD_COMMAND = "apt-get download $package"
EXTRACT_DATA_COMMAND = "ar x $package*.deb data.tar.xz"
UNTAR_COMMAND = "tar xvf data.tar.xz"
CLEANUP_COMMAND = "rm *.deb data.tar.xz usr/ etc/ -rf"
FIND_COMMAND = "test -d $directory && find $directory/* -size -10M"
DIS_COVER_COMMAND = "dis-cover -p $filename"


def run_command(command, shell=False):
    command = command.split() if not shell else command
    res = subprocess.run(command, capture_output=True, shell=shell)
    if res.returncode != 0:
        stderr = res.stderr.decode("utf-8")
        stdout = res.stdout.decode("utf-8")
        raise RuntimeError(stderr or stdout)
    try:
        return res.stdout.decode("utf-8")
    except UnicodeDecodeError:
        return res.stdout


# We apt update.
run_command(UPDATE_COMMAND)

# We get the list of packages to analyze.
# The first three words are the beginning of the output, not packages.
packages = run_command(GCC_RDEPENDENCIES_COMMAND).split()[3:]

data = {}

for package in packages[0:20]:
    data[package] = {}
    download_command = DOWNLOAD_COMMAND.replace("$package", package)
    run_command(download_command)

    extract_command = EXTRACT_DATA_COMMAND.replace("$package", package)
    run_command(extract_command, shell=True)

    run_command(UNTAR_COMMAND)

    files = []

    for directory in ["usr/bin", "usr/sbin", "usr/lib/*"]:
        find_command = FIND_COMMAND.replace("$directory", directory)
        try:
            files += run_command(find_command, shell=True).split()
        except RuntimeError:
            pass

    for filename in files:
        dis_cover_command = DIS_COVER_COMMAND.replace("$filename", filename)
        data[package][filename] = pickle.loads(run_command(dis_cover_command))

    remove_command = CLEANUP_COMMAND.replace("$package", package)
    run_command(remove_command, shell=True)

sys.stdout.buffer.write(pickle.dumps(data))
