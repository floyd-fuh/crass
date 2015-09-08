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

TARGET="./diff-output"

if [ $# -lt 2 ]
then
  echo "Usage: `basename $0` old-dir new-dir [output-dir]"
  exit 0
fi

if [ $# -eq 3 ]
then
  #argument without last /
  TARGET=${3%/}
fi

#remove last / of arguments
ONE=${1%/}
TWO=${2%/}
CUR="`pwd`"

echo "#Diffing $1 and $2"


mkdir "$TARGET"

cd "$ONE"
find . -type f -print | sort -u > "$CUR/$TARGET/file-list-ONE.txt"
cd "$CUR" #TWO can be relative, so go back first
cd "$TWO"
find . -type f -print | sort -u > "$CUR/$TARGET/file-list-TWO.txt"
cd "$CUR"

#Summary: Which files differ at all?
diff -E -b -w -r -q "./$ONE" "./$TWO" > "$TARGET/different-files.txt"

#Summary: Which files are new/were deleted
echo "Checking which files differ, were added or removed"
comm -23 "$TARGET/file-list-ONE.txt" "$TARGET/file-list-TWO.txt" > "$TARGET/removed-files.txt"
comm -13 "$TARGET/file-list-ONE.txt" "$TARGET/file-list-TWO.txt" > "$TARGET/new-files.txt"
comm -12 "$TARGET/file-list-ONE.txt" "$TARGET/file-list-TWO.txt" > "$TARGET/common-files.txt"

#The details of all diffs: This is what we should normally check...
echo "Producing the main diff"
diff -E -b -w -r "./$ONE" "./$TWO" > "$TARGET/diff-everything.txt"

#do it separately for each file extension, so if we're in a hurry, we can e.g. only look at .java files
#these types will generate a diff file each
types="java jsp m h properties xml c cpp"
for t in $types; do
	grep -E "\.$t$" "$TARGET/common-files.txt" > "$TARGET/common-$t.txt"
done
#getting files with other extensions than $types, will create one file for all of them
grep -vE ".*\.(`echo $types | tr " " "|"`)$" "$TARGET/common-files.txt" > "$TARGET/common-others.txt"

types="$types others"
for t in $types; do
	#generate the diff
	echo "Diffing $t files"
	#uncomment to generate the two-sided comparison - WARN: it's not possible to print filenames and line numbers this way
	#cat common-$t.txt | xargs -I {} -n1 diff -E -b -w -y --strip-trailing-cr --suppress-common-lines -W 200 --tabsize=4 -t $ONE/{} $TWO/{} > diff-$t.txt
	cat "$TARGET/common-$t.txt" | xargs -I {} diff -E -b -w -u "$ONE/{}" "$TWO/{}" > "$TARGET/diff-$t.txt"
done


echo "Cleaning up, removing empty files in $TARGET"
find $TARGET -type f -size 0 -maxdepth 1 -delete