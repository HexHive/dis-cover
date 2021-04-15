import subprocess

UPDATE_COMMAND = "apt-get update"
GCC_RDEPENDENCIES_COMMAND = "apt-cache rdepends libgcc1"  # Debian
# GCC_RDEPENDENCIES_COMMAND = "apt-cache rdepends libgcc-s1" # Ubuntu
DOWNLOAD_COMMAND = "apt-get download $package"
EXTRACT_DATA_COMMAND = "ar x $package*.deb data.tar.xz"
UNTAR_COMMAND = "tar xvf data.tar.xz"
CLEANUP_COMMAND = "rm *.deb data.tar.xz usr/ etc/ -rf"
DIS_COVER_COMMAND = (
    "test -d $directory && find $directory/* -size -20M -exec dis-cover \{\} \;"
)


def run_command(command, shell=False):
    command = command.split() if not shell else command
    res = subprocess.run(command, capture_output=True, shell=shell)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.decode("utf-8"))
    return res.stdout.decode("utf-8")


# We apt update.
run_command(UPDATE_COMMAND)

# We get the list of packages to analyze.
# The first three words are the beginning of the output, not packages.
packages = run_command(GCC_RDEPENDENCIES_COMMAND).split()[3:]

for package in packages[0:10]:
    download_command = DOWNLOAD_COMMAND.replace("$package", package)
    run_command(download_command)

    extract_command = EXTRACT_DATA_COMMAND.replace("$package", package)
    run_command(extract_command, shell=True)

    run_command(UNTAR_COMMAND)

    print(package)

    out = ""
    for directory in ["usr/bin", "usr/sbin", "usr/lib/*"]:
        analysis_command = DIS_COVER_COMMAND.replace("$directory", directory)
        try:
            out += run_command(analysis_command, shell=True)
        except RuntimeError as err:
            print(err)

    print(out)
    print("===================================================", flush=True)

    remove_command = CLEANUP_COMMAND.replace("$package", package)
    run_command(remove_command, shell=True)
