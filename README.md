
Terrier editor
--------------
Secure text editor with encryption for Linux. Forked from [l3afpad](https://github.com/stevenhoneyman/l3afpad) and added encryption

### How to use
Download latest terrier.zip from "Releases", unzip, run terrier

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
[ For Ubuntu ]
$ apt install automake intltool libgtk-3-dev libsodium-dev
$ unzip main.zip                      # unpack the sources
$ cd terrier-main                     # change to the toplevel directory
$ ./autogen.sh                        # generate the `configure' script
$ ./configure                         # run the `configure' script
$ make                                # build Terrier
[ Become root if necessary ]
# make install-strip                  # install Terrier
```

My similar project: [vimterrier](https://github.com/ziptt/vimterrier)
