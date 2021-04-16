import sys
import subprocess
import pickle
from multiprocessing import Pool

UPDATE_COMMAND = "apt-get update"
GCC_RDEPENDENCIES_COMMAND = "apt-cache rdepends libgcc1"  # Debian
# GCC_RDEPENDENCIES_COMMAND = "apt-cache rdepends libgcc-s1" # Ubuntu
DOWNLOAD_COMMAND = "apt-get download $package"
EXTRACT_DATA_COMMAND = "mkdir $package && cd $package && ar x ../$package*.deb data.tar.xz"
UNTAR_COMMAND = "tar xvf $package/data.tar.xz --directory $package"
CLEANUP_COMMAND = "rm $package* -rf"
FIND_COMMAND = "test -d $package/$directory && find $package/$directory/* -size -2M"
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


def analyze_package(package):
    data[package] = {}
    download_command = DOWNLOAD_COMMAND.replace("$package", package)
    run_command(download_command)

    extract_command = EXTRACT_DATA_COMMAND.replace("$package", package)
    run_command(extract_command, shell=True)

    untar_command = UNTAR_COMMAND.replace("$package", package)
    run_command(untar_command)

    files = []

    for directory in ["usr/bin", "usr/sbin", "usr/lib/*"]:
        find_command = FIND_COMMAND.replace("$directory", directory).replace("$package", package)
        try:
            files += run_command(find_command, shell=True).split()
        except RuntimeError:
            pass

    for filename in files:
        dis_cover_command = DIS_COVER_COMMAND.replace("$filename", filename)
        try:
            data[package][filename] = pickle.loads(run_command(dis_cover_command))
        except RuntimeError:
            pass

    remove_command = CLEANUP_COMMAND.replace("$package", package)
    run_command(remove_command, shell=True)


if __name__ == "__main__":
    # We apt update.
    run_command(UPDATE_COMMAND)

    # We get the list of packages to analyze.
    # The first three words are the beginning of the output, not packages.
    packages = run_command(GCC_RDEPENDENCIES_COMMAND).split()[3:]

    data = {}

    Pool().map(analyze_package, packages[0:10])

    sys.stdout.buffer.write(pickle.dumps(data))
