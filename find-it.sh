#!/bin/bash
#
# A simple file identifier for code, loot, IT-tech-stuff-the-customer-throws-at-you.
# Tries to find IT security and privacy related stuff.
# For pentesters.
#
# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <floyd at floyd dot ch> wrote this file. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return
# floyd http://floyd.ch @floyd_ch <floyd at floyd dot ch>
# July 2013
# ----------------------------------------------------------------------------
#
# Requirements:
# - find command. Reason: Get all files and exec file with them
# - file command. Reason: To identify file types
# - grep command. Reason: We need to filter certain results
# - sort command. Reason: Uniquely sorted (if you don't have sort -u you can use uniq as well)
# - mkdir command. Reason: we need to make the $TARGET directory
#
# Howto:
# - Customize the "OPTIONS" section below to your needs
# - Copy this file to the parent directory which you want to find
# - run it like this: ./find-it.sh ./directory-to-find-through/
#
# Output:
# You can check the output with any text viewer, "less -R ./find-output/*" works fine
# Output files have the following naming conventions (separated by underscore):
# - priority: 1-5, where 1 is more interesting (low false positive rate, certainty of "vulnerability") and 5 is only "you might want to have a look"
# - section: eg. by file extension, or using the "file" command
# - name of what we looked for

###
#OPTIONS - please customize
###
FIND_COMMAND="find"
FILE_COMMAND="file"
GREP_COMMAND="grep"
SORT_COMMAND="sort"
ADDITIONAL_FIND_ARGUMENTS=""
#Where to put the output (if not otherwise specified on command line)
TARGET="./find-output"
#Write the comment to each file at the beginning
WRITE_COMMENT="true"

#In my opinion I would always leave all the options below here on true,
#I would only change it if the script needs very long, you are looking through a lot of stuff
#or if you have any other performance issues with this script.

#try to find file types according to the "file" command
DO_FILE_COMMAND="true" 

#try to find file types according to their file extension
DO_FILEEXTENSION="true" 

#try to find files according to known interesting file names
DO_FILE_NAME="true" 

###
#END OPTIONS
#Normally you don't have to change anything below here...
###

###
#CODE SECTION
#As a user of this script you shouldn't need to care about the stuff that is coming down here...
###

# Conventions if you add new searches:
# - First think about which sections you want to put a new rule
# - Most of the time we use find not with regex but with the simple pattern of -iname (from the find man):
#    -name pattern
#         True if the last component of the pathname being examined matches
#         pattern.  Special shell pattern matching characters (``['',
#         ``]'', ``*'', and ``?'') may be used as part of pattern.  These
#         characters may be matched explicitly by escaping them with a
#         backslash (``\'').
# - If in doubt, prefer to make two searches and output files rather then joining with wildcards. If one produces false positives it is really annoying to search for the true positives of the other.
# - Take care with single/double quoted strings. From the bash manual:
# 3.1.2.2 Single Quotes
# Enclosing characters in single quotes (‘'’) preserves the literal value of each character within the quotes. A single quote may not occur between single quotes, even when preceded by a backslash.
# 3.1.2.3 Double Quotes
# Enclosing characters in double quotes (‘"’) preserves the literal value of all characters within the quotes, with the exception of ‘$’, ‘`’, ‘\’, and, when history expansion is enabled, ‘!’. The characters ‘$’ and ‘`’ retain their special meaning within double quotes (see Shell Expansions). The backslash retains its special meaning only when followed by one of the following characters: ‘$’, ‘`’, ‘"’, ‘\’, or newline. Within double quotes, backslashes that are followed by one of these characters are removed. Backslashes preceding characters without a special meaning are left unmodified. A double quote may be quoted within double quotes by preceding it with a backslash. If enabled, history expansion will be performed unless an ‘!’ appearing in double quotes is escaped using a backslash. The backslash preceding the ‘!’ is not removed. The special parameters ‘*’ and ‘@’ have special meaning when in double quotes (see Shell Parameter Expansion).
#
# TODO: 
# - Delete files when find doesn't have a result. Find's exit code can't be used for that :(

if [ $# -lt 1 ]
then
  echo "Usage: `basename $0` directory-to-grep-through [output-dir]"
  exit 0
fi

if [ "$1" = "." ]
then
  echo "You are shooting yourself in the foot. Do not find through . but rather cd into parent directory and mv `basename $0` there."
  echo "READ THE HOWTO (3 lines)"
  exit 0
fi

if [ $# -eq 2 ]
then
  #argument without last /
  TARGET=${2%/}
fi

#argument without last /
SEARCH_FOLDER=${1%/}

mkdir "$TARGET"

echo "Output will be put into this folder: $TARGET"
echo "You are currently finding through folder: $SEARCH_FOLDER"

if [ "$DO_FILE_COMMAND" = "true" ]; then

    OUTFILE="3_file_all_files_listed.txt"
    echo "# Info: All files and their type according to the file command" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: file {}" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -exec $FILE_COMMAND '{}' \; >> $TARGET/$OUTFILE

    OUTFILE="2_file_all_types.txt"
    echo "# Info: All types uniquely listed (according to the file command)" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: file -b {} | sort -u" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -exec $FILE_COMMAND -b '{}' \; | $SORT_COMMAND -u >> $TARGET/$OUTFILE

    OUTFILE="1_file_dot_net_decompilable_files.txt"
    echo "# Info: .NET executable files (and therefore decompilable) according to file command" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: file {}|grep -i executable|grep -i '.net'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -exec $FILE_COMMAND '{}' \; | $GREP_COMMAND -i executable | $GREP_COMMAND -i '.net' >> $TARGET/$OUTFILE

    #jars are just zips according to file: Zip archive data, at least v1.0 to extract
    #class: compiled Java class data, version 50.0 (Java 1.6)
    OUTFILE="1_file_java_decompilable_files.txt"
    echo "# Info: Java class files (and therefore decompilable) according to file command, but attention: file detects jar files as zips, so jars are not listed." >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: file {}|grep -i \"Java class\"" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -exec $FILE_COMMAND '{}' \; | $GREP_COMMAND -i "Java class" >> $TARGET/$OUTFILE

fi

if [ "$DO_FILEEXTENSION" = "true" ]; then

    OUTFILE="4_find_class.txt"
    echo "# Info: All class files (decompilable!) according to their file extension" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find -iname '*.class'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -iname '*.class' >> $TARGET/$OUTFILE

    OUTFILE="4_find_jar.txt"
    echo "# Info: All class files (decompilable!) according to their file extension" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find -iname '*.jar'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -iname '*.jar' >> $TARGET/$OUTFILE
    
    OUTFILE="4_find_php.txt"
    echo "# Info: All php files (cleartext!) according to their file extension (.php .php5 etc.)" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find -iname '*.php?'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -iname '*.php?' >> $TARGET/$OUTFILE
    
    OUTFILE="3_find_db.txt"
    echo "# Info: All sqlite or other database files (cleartext?) according to their file extension (.db)" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find -iname '*.db'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -iname '*.db' >> $TARGET/$OUTFILE
    
    OUTFILE="3_find_c.txt"
    echo "# Info: All c files (cleartext?) according to their file extension (.c)" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find -iname '*.c'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -iname '*.c' >> $TARGET/$OUTFILE
    
    OUTFILE="5_find_html.txt"
    echo "# Info: All html files according to their file extension (.html .htm)" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find -iname '*.htm?'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -iname '*.htm?' >> $TARGET/$OUTFILE
    
    OUTFILE="5_find_javascript.txt"
    echo "# Info: All javascript files according to their file extension (.js)" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find -iname '*.js?'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -iname '*.js?' >> $TARGET/$OUTFILE
    
    OUTFILE="5_find_log.txt"
    echo "# Info: All log files according to their file extension (.log .log1 .log2)" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find -iname '*.log?'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -iname '*.log?' >> $TARGET/$OUTFILE
    
    OUTFILE="5_find_all_others.txt"
    echo "# Info: All files with file extensions we didn't looked for yet" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find | grep -v '.class|.jar|.php|.db|.htm|.js'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" | $GREP_COMMAND -v '.class|.jar|.php|.db|.c|.htm|.js' >> $TARGET/$OUTFILE

fi

if [ "$DO_FILE_NAME" = "true" ]; then
    
    OUTFILE="1_filename_web-xml.txt"
    echo "# Info: web.xml is the Spring frameworks main mapping XML and important to understand which URLs are mapped to where" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find -iname 'web.xml'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -iname 'web.xml' >> $TARGET/$OUTFILE
    
    OUTFILE="1_filename_commons-collection.txt"
    echo "# Info: commons-collection can be used to exploit deserialization issues. Deserialization is something that can result in remote command execution, there are various exploits for such things, see http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ for example" >> $TARGET/$OUTFILE
    echo "# Filename: $OUTFILE" >> "$TARGET/$OUTFILE"
    echo "# Search: find -iname '*commons*collection*'" >> "$TARGET/$OUTFILE"
    echo "Searching for results for $OUTFILE"
    $FIND_COMMAND "$SEARCH_FOLDER" -iname '*commons*collection*' >> $TARGET/$OUTFILE
    
    #TODO filenames:
    #wsadmin.properties configuration file of Websphere
    
    
    #TODO:
    #random
    #sql
    #database
    #keychain
    #shadow
    #passwd
    #key
    #salt
    #pass
    #secret
    #pin
    #authorization
    #authentication
    
    
fi
