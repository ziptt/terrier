
Terrier editor
--------------
Secure text editor with encryption

### How to use
Download qq from "Releases", unzip, run qq

### Build from source
Terrier requires:
* GTK+-3.x.x libraries
* ncurses library
* sodium library

and for building also:
* automake
* intltool

Simple compile and install procedure:
```
$ tar xzvf terrier-x.x.x.tar.gz       # unpack the sources
$ cd terrier-x.x.x                    # change to the toplevel directory
$ ./autogen.sh                        # generate the `configure' script
$ ./configure                         # run the `configure' script
$ make                                # build Terrier
[ Become root if necessary ]
# make install-strip                  # install Terrier
```
