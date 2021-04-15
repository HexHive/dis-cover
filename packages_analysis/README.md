We can get a list of packages that depend on C++ compilation by running :

```
apt-cache rdepends libgcc-s1
```

5885 hits ! Let's get analyzing :D

TODO : install packages in a directory

More info :

```
man apt-get
man apt_preferences
```

We should try to see if there is "template", "throw" and "catch" in the C++

Also, mangled text, cxa__

Also libunwind, ehframe

## Find binaries

```
apt-get download apt
ar x apt_2.0.5_amd64.deb
tar xvf data.tar.xz
find usr/bin/* -exec dis-cover {} \;
```
