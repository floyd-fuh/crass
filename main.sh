#!/bin/bash
#
# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <floyd at floyd dot ch> wrote this file. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return
# floyd http://floyd.ch @floyd_ch <floyd at floyd dot ch>
# July 2013
# ----------------------------------------------------------------------------

if [ $# -eq 1 ]; then
    echo "[+] Starting analysis of $1"

    #remove last / of directory arguments
    DIR=${1%/}

    #Only use the original directory for find, grep and extract
    #Sometimes you might only want to do this (not running bloat and clean):
    #echo "[+] Invoking ./find-it.sh \"$DIR\""
    #./find-it.sh "$DIR"
    #echo "[+] Invoking ./grep-it.sh \"$DIR\""
    #./grep-it.sh "$DIR"
    #echo "[+] Invoking ./extract-it.sh \"$DIR\""
    #./extract-it.sh "$DIR"


    DIR_MODIFIED="$DIR-modified"
    echo "[+] Copying $DIR to $DIR_MODIFIED"
    cp -r "$DIR" "$DIR_MODIFIED"
    
    echo "[+] Invoking ./bloat-it.sh \"$DIR_MODIFIED\""
    ./bloat-it.sh "$DIR_MODIFIED"
    echo "[+] Invoking ./clean-it.sh \"$DIR_MODIFIED\""
    ./clean-it.sh "$DIR_MODIFIED"
    echo "[+] Invoking ./find-it.sh \"$DIR_MODIFIED\""
    ./find-it.sh "$DIR_MODIFIED" "./find-output-modified"
    echo "[+] Invoking ./grep-it.sh \"$DIR_MODIFIED\""
    ./grep-it.sh "$DIR_MODIFIED" "./grep-output-modified"
    echo "[+] Invoking ./extract-it.sh \"$DIR_MODIFIED\""
    ./extract-it.sh "$DIR_MODIFIED" "./extract-output-modified"
    
    echo "[+] You can now start analyzing the '-modified' directories, we're finished with those."
    echo "[+] Now also applying to non-modified dir, if you don't get satisfactory result in the modified, look at those results without such a suffix"
    echo "[+] Invoking ./find-it.sh \"$DIR\""
    ./find-it.sh "$DIR"
    echo "[+] Invoking ./grep-it.sh \"$DIR\""
    ./grep-it.sh "$DIR"
    echo "[+] Invoking ./extract-it.sh \"$DIR\""
    ./extract-it.sh "$DIR"
    
    echo "[+] Ended analysis of $1"
    echo "[+] Might be better if you do this manually:"
    echo "rm -r \"$DIR_MODIFIED\""
    
    
elif [ $# -eq 2 ]; then
    echo "[+] Starting analysis of $1 and $2"

    #remove last / of directory arguments
    OLD_DIR=${1%/}
    NEW_DIR=${2%/}

    OLD_DIR_MODIFIED="$OLD_DIR-for-diff"
    NEW_DIR_MODIFIED="$NEW_DIR-for-diff"

    echo "[+] Copying $OLD_DIR to $OLD_DIR_MODIFIED"
    cp -r "$OLD_DIR" "$OLD_DIR_MODIFIED"

    echo "[+] Copying $NEW_DIR to $NEW_DIR_MODIFIED"
    cp -r "$NEW_DIR" "$NEW_DIR_MODIFIED"

    ./bloat-it.sh "$OLD_DIR_MODIFIED"
    ./bloat-it.sh "$NEW_DIR_MODIFIED"
    ./clean-it.sh "$OLD_DIR_MODIFIED"
    ./clean-it.sh "$NEW_DIR_MODIFIED"
    ./diff-it.sh "$OLD_DIR_MODIFIED" "$NEW_DIR_MODIFIED" "./diff-output-modified"

    #Don't run these. Users can invoke main.sh again with one of the folders if they
    #would like to find, grep, extract, etc.
    #./find-it.sh "$NEW_DIR"
    #if you get too much garbage, look into find-it.sh script or use:
    #./find-it.sh "$NEW_DIR_MODIFIED"
    #./grep-it.sh "$NEW_DIR"
    #if you get too much garbage, look into grep-it.sh script or use:
    #./grep-it.sh "$NEW_DIR_MODIFIED"

    echo "[+] Might be better if you do this manually:"
    echo "rm -r \"$OLD_DIR_MODIFIED\""
    echo "rm -r \"$NEW_DIR_MODIFIED\""
    
    echo "We only ran the diff script. If you would like to grep, find, etc. invoke main.sh only with one of the directories."
else
    echo "Usage: `basename $0` directory [new-directory]"
    echo "If you specify <new-directory>, <directory> will be used as the former and diff will be invoked instead of grep, find, etc."
    exit 1
fi

