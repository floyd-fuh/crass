#test the script with the contents of tests/

#bloat, clean, grep, find, extract, etc. testing:
cp -r tests tests-copy
./main.sh tests-copy/

#diff testing:
./main.sh tests-copy/diff-test/old/ tests-copy/diff-test/new/

rm -r tests-copy
