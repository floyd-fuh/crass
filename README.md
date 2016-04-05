CRASS 
=============

The "code review audit script scanner" (CRASS) started as a source code grep-er with a set of selected high-potential strings that may result in (security) problems. By now it is searching for strings that are interesting for analysts. Simplicity is the key: You don't need anything than a couple of standard *nix command line tools (especially grep), while the project still serves as a "what can go wrong" collection of things we see over the years.

Use cases
-------

I know it is not a real static analysis tool and it's not in any way a replacement for all the tools out there, but it is kind of language independent. It's also not only for source code. It should be helpful in all cases where you have too much data to look through manually during a security review: You customer sent you a zip file with "the new release"/"the code"/"the stuff the developer gave me". Or you achieved to gain access to a server, looted a lot of files and want to look for further problems and sensitive information. You harvested/looted data off a server/client/share/...

It should usually be used when you don't know where to start or when it's just way too much to go through manually.

Where to start
-------

If you've never used CRASS before you should try grep-it.sh (currently the main focus of the project). Customize the OPTIONS section of the file. If you are on Linux, you should for example change GREP_COMMAND to "grep" instead of "/opt/local/bin/grep". The rest should be fine for a first run.

Contents of the project
-------

By now the tool is also able to analyze directories full of unknown things a bit smarter: 

* A script to unpack and make things bigger (bloat-it.sh: unpack zips, decompile jars, etc.)
* A script to clean and make things smaller (clean-it.sh: depending on the use case we want to remove .svn, .git folders, etc.)
* A script to get an overview about existing files (find-it.sh: using the "file" command)
* A script to compare two versions (diff-it.sh: using the "diff" command)
* A script to visualize the contents (visualize-it.sh: maybe show file entropy or such things)
* A script to extract interesting information (extract-it.sh: mainly meta data, for example exif information from pictures)
* A script to find interesting things for security people (grep-it.sh: using the gnu version of "grep"): 

Some characteristics:
* The scripts can be run independently (it is important to keep it this way). main.sh is showing what the idea of using them all together is.
* Tested under MAC OSX (with gnu-grep from mac ports). You should customize the defined variables on the first few line in each script.
