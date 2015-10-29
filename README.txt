CRASS -- the "code review audit script scanner" started as a source code grep-er with a set of carefully selected high-potential strings that may result in (security) problems. By now it is searching for strings that are interesting for an analysts. Simplicity is the key: You don't need anything than a couple of standard *nix command line tools, while the project still serves as a "what can go wrong" collection of things we see over the years.

By now the tool is also able to analyze directories full of unknown things a bit smarter: 

- A script to unpack and make things bigger (bloat-it.sh: unpack zips, decompile jars, etc.)
- A script to clean and make things smaller (clean-it.sh: depending on the use case we want to remove .svn, .git folders, etc.)
- A script to get an overview about existing files (find-it.sh: using the "file" command)
- A script to compare two versions (diff-it.sh: using the "diff" command)
- A script to visualize the contents (visualize-it.sh: maybe show file entropy or such things)
- A script to extract interesting information (extract-it.sh: mainly meta data, for example exif information from pictures)
- A script to find interesting things for security people (grep-it.sh: using the gnu version of "grep"): 
 - It is not a real static analysis tool and it's not in any way a replacement for all the tools out there, but it is kind of language independent...
 - It's also not only for source code. It should be helpful in all cases where you have too much data to look through manually: You customer sent you a zip file with whatever. You achieved access to a server and want to look for further problems and sensitive information. You harvested/looted data off a server/client/share/...

Some characteristics:
- The scripts can be run independently (it is important to keep it this way). main.sh is showing what the idea of using them all together is.
- Tested under MAC OSX ONLY (with gnu-grep from mac ports)

These scripts aren't very advanced - exactly what's needed if you don't know where to start.
