import sys
import subprocess
import pickle
import uuid
from multiprocessing import Pool

ADD_SOURCE_LIST = 'echo "deb-src http://http.us.debian.org/debian unstable main" >> /etc/apt/sources.list'
UPDATE_COMMAND = "apt-get update"
GCC_RDEPENDENCIES_COMMAND = "apt-cache rdepends libgcc1"  # Debian
# GCC_RDEPENDENCIES_COMMAND = "apt-cache rdepends libgcc-s1" # Ubuntu
DOWNLOAD_COMMAND = "mkdir $dir && cd $dir && apt-get source $package"
GREP_COMMAND = "grep -r -- -fno-rtti $dir"
CLEANUP_COMMAND = "rm $dir -rf"


data = {}


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
    data = ""
    dir_name = str(uuid.uuid4())

    try:
        download_command = DOWNLOAD_COMMAND.replace("$package", package).replace(
            "$dir", dir_name
        )
        run_command(download_command, shell=True)
    except:
        remove_command = CLEANUP_COMMAND.replace("$dir", dir_name)
        run_command(remove_command, shell=True)
        return "could_not_extract"

    grep_command = GREP_COMMAND.replace("$dir", dir_name)

    try:
        data = run_command(grep_command, shell=True).split()
    except:
        pass

    remove_command = CLEANUP_COMMAND.replace("$dir", dir_name)
    run_command(remove_command, shell=True)
    return data


if __name__ == "__main__":
    # We add the source link
    run_command(ADD_SOURCE_LIST, shell=True)

    # We apt update.
    run_command(UPDATE_COMMAND)

    # We get the list of packages to analyze.
    # The first three words are the beginning of the output, not packages.
    packages = run_command(GCC_RDEPENDENCIES_COMMAND).split()[3:]

    data = dict(zip(packages, Pool().map(analyze_package, packages)))

    sys.stdout.buffer.write(pickle.dumps(data))
