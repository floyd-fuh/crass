
function dissassemlbeAndDecompileAndroidApps()
{
    #Configurable Parameters
    APKLOCATION=$1 #android-apps - where the APK files are stored
    APPLE_SCRIPT=$2 #jd-gui-save-all.scpt - Location of the apple script to do automatic source saving in JD-GUI
    JD_GUI_SAVE_LOCATION=$3 # /opt - Where the apple script with JD-GUI is going to save the zip files with the java sources
    
    #The apple script for JD-Gui could look for example as following:
    #     tell application "JD-GUI"
    #         activate
    #     end tell
    #     #delay 1
    #     tell application "System Events"
    #       keystroke "s" using {command down, option down}
    #     end tell
    #     tell application "System Events"
    #       keystroke tab
    #       keystroke tab
    #       keystroke tab
    #       key code 125 #Down
    #       key code 125 #Down
    #       key code 125 #Down
    #       key code 125 #Down
    #       key code 125 #Down
    #       key code 36 #Enter
    #       delay 1
    #       key code 36 #Enter
    #       delay 2
    #     end tell
    # 
    #     repeat while appIsRunning("JD-GUI")
    #       tell application "System Events"
    #           keystroke "q" using {command down}
    #       end tell
    #       delay 2
    #     end repeat
    # 
    #     on appIsRunning(appName)
    #       tell application "System Events" to (name of processes) contains appName
    #     end appIsRunning

    ORGWD=`pwd`
    #Decompiling
    JAVA_TARGET=$TARGETPATH/java-new #A folder to store the java code (should not exist)
    #Disassembling
    SMALI_TARGET=$TARGETPATH/smali-new #A temporary folder
    
    
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
    
}