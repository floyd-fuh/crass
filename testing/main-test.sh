#test the script with the contents of tests/

cd ..

#bloat, clean, grep, find, extract, etc. testing:
cp -r ./testing/tests tests-copy
./main.sh tests-copy/

#diff testing:
./main.sh tests-copy/diff-test/old/ tests-copy/diff-test/new/

rm -r tests-copy

echo "You want to run this after you are finished:"
echo "rm -rf find-output-modified grep-output-modified diff-output-modified tests-copy-modified"