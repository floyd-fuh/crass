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

if [ $# -ne 1 ]
then
  echo "Usage: `basename $0` /path/to/jar/to/decompile.jar"
  exit 0
fi

JD_CORE="/opt/jd-core-java/build/libs/jd-core-java-1.2.jar"

if [ ! -f "$JD_CORE" ]
then
    echo "Error: Didn't find jd-core.jar in $JD_CORE, is it really there? Please make sure you specify the jd-core.jar location or configure other decompiler script."
    exit 1
fi

echo "#Invoking jd-core with $1"

JAR_FILE="$1" #e.g. /home/Users/user/project/software.jar
#Unsure if this might be a better idea:
#TARGET_FOLDER="$1-decompiled"
#Pros: all decompiled stuff in separate folder, can't overwrite anything that's already there
#Cons: Have to look through separate folder to search for corresponding .java class, more folders, etc.
TARGET_FOLDER=`dirname "$1"` #e.g. /home/Users/user/project/

java -jar "$JD_CORE" "$JAR_FILE" "$TARGET_FOLDER/"

