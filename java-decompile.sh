#!/bin/bash
#
# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <floyd at floyd dot ch> wrote this file. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return
# floyd http://floyd.ch @floyd_ch <floyd at floyd dot ch>
# February 2025
# ----------------------------------------------------------------------------

if [ $# -ne 1 ]
then
  echo "Usage: `basename $0` /path/to/jar/to/decompile.jar"
  exit 0
fi

VINEFLOWER="/opt/vineflower-java-decompiler/vineflower-1.10.1.jar"

if [ ! -f "$VINEFLOWER" ]
then
    echo "Didn't find vineflower.jar in $VINEFLOWER, is it really there? Please make sure you specify the location or configure other decompiler script."
    exit 1
fi

#echo "#Decompiling $1 with vineflower"

JAR_FILE="$1" #e.g. /home/Users/user/project/software.jar
TARGET_FOLDER="`dirname $1`/" #e.g. /home/Users/user/project/

java -jar "$VINEFLOWER" --silent "$JAR_FILE" "$TARGET_FOLDER"

