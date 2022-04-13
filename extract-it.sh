#!/bin/bash
#
# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <floyd at floyd dot ch> wrote this file. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return
# floyd http://floyd.ch @floyd_ch <floyd at floyd dot ch>
# January 2022
# ----------------------------------------------------------------------------


if [ $# -ne 1 ]
then
  echo "Usage: `basename $0` dir-to-extract"
  exit 0
fi

DIR=${1%/}

TARGET="./extract-output"
if [ $# -eq 2 ]
then
  #argument without last /
  TARGET=${2%/}
fi
mkdir "$TARGET"


echo "#Extracting $DIR"

GREP_COMMAND="/opt/local/bin/ggrep"
if [ ! -f "$GREP_COMMAND" ]
then
    GREP_COMMAND="ggrep"
    if ! command -v $GREP_COMMAND &> /dev/null
    then
        GREP_COMMAND="grep"
        if ! command -v $GREP_COMMAND &> /dev/null
        then
            echo "Could not find a usable 'grep'"
            exit 1
        fi
    fi
fi

echo "Extracting all Java @JsonProperty annotations to feed them into the ParamMiner Portswigger Burp extension"
$GREP_COMMAND -roP '@JsonProperty\(\K[^)]{1,300}' "$DIR"|cut -d ":" -f 2|sort -u > "$TARGET/java_json_property_bindings.txt"

echo "Extract all Java Spring framework getHeader for example for org.springframework.web.context.request.NativeWebRequest"
$GREP_COMMAND -roP '\.getHeader\(\K[^)]{1,300}' "$DIR"|cut -d ":" -f 2|sort -u > "$TARGET/java_spring_getHeader.txt"

echo "Extract all occurences of .equals() and .equalsIgnoreCase(). Then compare if the same parameter name is used in both."
echo "This possibly indicates that a certain filter/check that is done with .equals() can later be circumvented with different capitalization"

$GREP_COMMAND -roP '\.equals\(\K[^)]{1,300}' "$DIR"|cut -d ":" -f 2|sort -u > "$TARGET/equals_parameters.txt"
$GREP_COMMAND -roP '\.equalsIgnoreCase\(\K[^)]{1,300}' "$DIR"|cut -d ":" -f 2|sort -u > "$TARGET/equalsIgnoreCase_parameters.txt"
OUTFILE="equals_parameters_to_check_for_filter_bypass_via_casing.txt"
if [ "$WRITE_COMMENT" = "true" ]; then
    echo "# The following parameters are passed to .equals() *and* to .equalsIgnoreCase(). This possibly indicates that a certain filter/check that is done with .equals() can later be circumvented with different capitalization because that's accepted." >> "$TARGET/$OUTFILE"
fi
# comm -1 -2 "$TARGET/equals_parameters.txt" "$TARGET/equalsIgnoreCase_parameters.txt" > "$TARGET/equals_parameters_to_check_for_filter_bypass_via_casing.txt"
# common lines in two files = grep -F -x -f
$GREP_COMMAND -F -x -f "$TARGET/equals_parameters.txt" "$TARGET/equalsIgnoreCase_parameters.txt" > "$TARGET/$OUTFILE"
rm "$TARGET/equals_parameters.txt" "$TARGET/equalsIgnoreCase_parameters.txt"

#TODO: E.g. extract metadata out of word files and images
#for example for images with ImageMagick:
#identify -verbose image.jpg
#exiftool-5.12 is another option
#e.g. make longitude/latitude link on google maps
