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

#NEVER RUN THIS SCRIPT on directories which you haven't backup'ed
#THIS IS A VERY DANGEROUS SCRIPT THAT DELETES
#I REPEAT, THIS IS A VERY DANGEROUS SCRIPT THAT DELETES

if [ $# -ne 1 ]
then
  echo "Usage: `basename $0` dir-to-bloat"
  exit 0
fi

DIR=${1%/}

echo "#Bloating $DIR"

UNZIP_CMD="unzip"
JAR_CMD="jar"
JAR_CMD="tar"
GZIP_CMD="gzip"

if [ -e ./java_decompile.sh ]
then
    JAR_BEHAVIOR="./java_decompile.sh"
else
    echo "###"
    echo "# Warning: You haven't chosen how to decompile .jar files."
    echo "# Please copy one of the java_decompile-*.sh files to java_decompile.sh"
    echo "# for now .jar are going to be unzipped and nothing more."
    echo "###"
    sleep 1
    JAR_BEHAVIOR="$JAR_CMD xf"
fi


for loops in 1 2 3 4 5
do
    echo "#Round $loops"
    echo "#unzip all files and delete the zip file afterwards"
    find "$DIR" -depth -iname '*.zip' -exec echo '#Unpacking {}' \; -execdir $UNZIP_CMD -n '{}' \; -delete
    
    echo "#untar all tar files and delete afterwards"
    find "$DIR" -depth -iname '*.tar' -exec echo '#Unpacking {}' \; -execdir $TAR_CMD -xf '{}' \; -delete
    
    echo "#ungzip all gz files and delete afterwards"
    find "$DIR" -depth -iname '*.gz' -exec echo '#Unpacking {}' \; -execdir $GZIP_CMD -d '{}' \; -delete
    
    echo "#handling all jar files and delete afterwards"
    find "$DIR" -depth -iname '*.jar' -exec echo '#Unpacking {}' \; -execdir $JAR_BEHAVIOR '{}' \; -delete
    
done



