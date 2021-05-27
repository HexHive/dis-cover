import sys
import subprocess
import pickle
import uuid
from multiprocessing import Pool

UPDATE_COMMAND = "apt-get update"
GCC_RDEPENDENCIES_COMMAND = "apt-cache rdepends libgcc1"  # Debian
# GCC_RDEPENDENCIES_COMMAND = "apt-cache rdepends libgcc-s1" # Ubuntu
DOWNLOAD_COMMAND = "mkdir $dir && cd $dir && apt-get download $package"
EXTRACT_DATA_COMMAND = "cd $dir && ar x *.deb data.tar.xz data.tar.gz && rm *.deb"
UNTAR_COMMAND = "tar xvf $dir/data.tar.* --directory $dir && rm $dir/data.tar.*"
FIND_COMMAND = "test -d $dir/$subpath && find $dir/$subpath"  # -size -2M"
DIS_COVER_COMMAND = "dis-cover -p $filename"
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
    data = {}
    dir_name = str(uuid.uuid4())

    try:
        download_command = DOWNLOAD_COMMAND.replace("$package", package).replace(
            "$dir", dir_name
        )
        run_command(download_command, shell=True)

        extract_command = EXTRACT_DATA_COMMAND.replace("$dir", dir_name)
        run_command(extract_command, shell=True)

        untar_command = UNTAR_COMMAND.replace("$dir", dir_name)
        run_command(untar_command, shell=True)
    except:
        remove_command = CLEANUP_COMMAND.replace("$dir", dir_name)
        run_command(remove_command, shell=True)
        return {"could_not_extract": True}

    files = []

    for directory in ["usr/bin", "usr/sbin", "usr/lib", "usr/games"]:
        find_command = FIND_COMMAND.replace("$subpath", directory).replace(
            "$dir", dir_name
        )
        try:
            files += run_command(find_command, shell=True).split()
        except RuntimeError:
            pass

    if len(files) == 0:
        remove_command = CLEANUP_COMMAND.replace("$dir", dir_name)
        run_command(remove_command, shell=True)
        return {"no_file_found": True}

    for filename in files:
        dis_cover_command = DIS_COVER_COMMAND.replace("$filename", filename)
        try:
            data[filename] = pickle.loads(run_command(dis_cover_command))
        except RuntimeError:
            pass

    remove_command = CLEANUP_COMMAND.replace("$dir", dir_name)
    run_command(remove_command, shell=True)
    return data


if __name__ == "__main__":
    # We apt update.
    run_command(UPDATE_COMMAND)

    # We get the list of packages to analyze.
    # The first three words are the beginning of the output, not packages.
    packages = run_command(GCC_RDEPENDENCIES_COMMAND).split()[3:]

    data = dict(zip(packages, Pool().map(analyze_package, packages)))

    sys.stdout.buffer.write(pickle.dumps(data))
