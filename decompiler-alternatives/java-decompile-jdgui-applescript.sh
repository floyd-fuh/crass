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

JDLOCATION="/Applications/JD-GUI"

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
  keystroke $TARGET_NAME
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

osacompile -o "$TMP/$APPLE_SCRIPT.scpt" "$TMP/$APPLE_SCRIPT"

$JDLOCATION $JAR_FILE &
sleep 1
osascript "$TMP/$APPLE_SCRIPT.scpt"

if [ -e $JAR_FILE.src.zip ]
          then
          mkdir "$TARGET_FOLDER/$TARGET_NAME"
          mv "$TARGET_FOLDER/$TARGET_NAME.zip" "$TARGET_FOLDER/$TARGET_NAME/"
          cd "$TARGET_FOLDER/$TARGET_NAME/"
          unzip -o -q "$TARGET_NAME.zip"
          cd -
          rm "$TARGET_FOLDER/$TARGET_NAME.zip"
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
