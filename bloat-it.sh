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
TAR_CMD="tar"
GZIP_CMD="gzip"
JAR_DECOMPILE="./java-decompile.sh"

if [ -e $JAR_DECOMPILE ]
then
    DECOMPILE_POSSIBLE=true
else
    echo "###"
    echo "# Warning: You haven't chosen how to decompile Java files."
    echo "# Please copy one of the java-decompile-*.sh files to java-decompile.sh"
    echo "# for now .jar and .war are going to be unpacked, but not decompiled."
    echo "###"
    DECOMPILE_POSSIBLE=false
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
    
    if [ "$DECOMPILE_POSSIBLE" = true ] ; then
        #TODO: At the moment jd-core does not support war files, although it's exactly the same as a jar file, see bug report at https://github.com/nviennot/jd-core-java/issues/24
        #echo "#decompiling all war files"
        ##We need to find ./java-decompile.sh, so no execdir here
        ##We don't delete them, as we also need the rest of the (meta) data (not only class files in decompiled form)
        #find "$DIR" -depth -iname '*.war' -exec echo '#Decompiling {}' \; -exec $JAR_DECOMPILE '{}' \;
        
        echo "#decompiling all jar files"
        #We need to find ./java-decompile.sh, so no execdir here
        #We don't delete them, as we also need the rest of the (meta) data (not only class files in decompiled form)
        find "$DIR" -depth -iname '*.jar' -exec echo '#Decompiling {}' \; -exec $JAR_DECOMPILE '{}' \;
        
        #jd-core does not support decompilation of a single class file directly, it must be in a jar *sigh*
        #What this means at the moment is that you have to pack them into a jar file :(
        #Side note: You can just pack an *entire* directory into one jar file and jd-core will happily decompile all contained class files
        #echo "#handling all class files and delete afterwards"
        ##We need to find ./java-decompile.sh, so no execdir here
        #find "$DIR" -depth -iname '*.class' -exec echo '#Unpacking/Decompiling {}' \; -exec $JAR_DECOMPILE '{}' \; -delete
    fi
    
    echo "#unpacking all war files and delete afterwards"
    find "$DIR" -depth -iname '*.war' -exec echo '#Unpacking {}' \; -execdir $JAR_CMD xf '{}' \; -delete

    echo "#unpacking all jar files and delete afterwards"
    find "$DIR" -depth -iname '*.jar' -exec echo '#Unpacking {}' \; -execdir $JAR_CMD xf '{}' \; -delete
    
done



