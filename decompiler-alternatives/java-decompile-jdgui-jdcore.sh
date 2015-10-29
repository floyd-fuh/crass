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

JD_CORE="/opt/jd-core/jd-core.jar"

if [ ! -f "$JD_CORE" ]
then
    echo "Didn't find jd-core.jar in $JD_CORE, is it really there? Please make sure you specify the jd-core.jar location or configure other decompiler script."
    exit 1
fi

echo "#Decompiling $1"

JAR_FILE="$1" #e.g. /home/Users/user/project/software.jar
TARGET_FOLDER="`dirname $1`/" #e.g. /home/Users/user/project/

java -jar "$JD_CORE" "$JAR_FILE" "$TARGET_FOLDER"

