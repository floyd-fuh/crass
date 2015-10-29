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
  echo "Usage: `basename $0` jar-to-decompile"
  exit 0
fi


echo "#Decompiling $1"

JAR_FILE="${1%/}" #e.g. /home/Users/user/project/software.jar-jdgui
TARGET_NAME="`basename $1`-jdgui" #e.g. software.jar-jdgui
TARGET_FOLDER="`dirname $1`" #e.g. /home/Users/user/project/

TMP="./decompile-tmp"
mkdir "$TMP"

APPLE_SCRIPT="jd-gui-save-all.scpt" #Will be written to tmp

echo "tell application \"JD-GUI\"
    activate
end tell
#delay 1
tell application \"System Events\"
  keystroke \"s\" using {command down, option down}
end tell
tell application \"System Events\"
  keystroke $TARGET_FOLDER/
  key code 36 #Enter
  delay 1
  key code 36 #Enter
  delay 2
end tell

repeat while appIsRunning(\"JD-GUI\")
  tell application \"System Events\"
      keystroke \"q\" using {command down}
  end tell
  delay 2
end repeat

on appIsRunning(appName)
  tell application \"System Events\" to (name of processes) contains appName
end appIsRunning
" > "$TMP/$APPLE_SCRIPT"



#Preparing for disassembling
_classpath=""
for k in $DEX2JARLOCATION/lib/*.jar
do
 _classpath="${_classpath}:${k}"
done
DEX2JAR="java -Xms512m -Xmx1024m -classpath ${_classpath} com.googlecode.dex2jar.v3.Main"


#Look for the files to decompile/dissassemble
cd $APKLOCATION
echo $APKLOCATION
FILES="`ls *.apk`"

if [ -e $SMALI_TARGET ]
then
    fatalError "Please remove $SMALI_TARGET first!"
else
    mkdir $SMALI_TARGET
fi

if [ -e $JAVA_TARGET ]
then
    fatalError "Please remove $JAVA_TARGET first!"
else
    mkdir $JAVA_TARGET
fi

info "Close all JD-GUI windows NOW! Then remove your hands from the keyboard and mouse and don't touch it anymore"
sleep 5

for f in $FILES
do
  info "Processing $f file..."  
  info "Disassembling (to smali)..."
  $APKTOOLSTART d $f $SMALI_TARGET/$f-source

  info "Decompiling (to java)..."

  cd $DEX2JARLOCATION
  $DEX2JAR $APKLOCATION/$f
  if [ -e $APKLOCATION/$f.dex2jar.jar ]
      then  
      mv $APKLOCATION/$f.dex2jar.jar $JAVA_TARGET/
      cd $JAVA_TARGET/
      $JDLOCATION $f.dex2jar.jar &
      sleep 1
      osascript $APPLE_SCRIPT
      if [ -e $JD_GUI_SAVE_LOCATION/$f.dex2jar.src.zip ]
          then
          mkdir $JAVA_TARGET/$f
          mv $JD_GUI_SAVE_LOCATION/$f.dex2jar.src.zip $JAVA_TARGET/$f/
          cd $JAVA_TARGET/$f/
          unzip -o -q $f.dex2jar.src.zip
          rm $f.dex2jar.src.zip
      else
          error "The Apple script didn't properly save the zip file."
      fi
      rm $JAVA_TARGET/$f.dex2jar.jar
  else
      error "The decompiling with dex2jar did not work for: $f"
      error "I don't know why yet, but some apk simply don't work"
      error "Ignoring this app"
  fi
  cd $APKLOCATION
done

cd $ORGWD
