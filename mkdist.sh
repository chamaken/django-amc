#!/bin/sh

PYTHON=$(which python3 || which python)
CWD=$(pwd)
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" 1 2 15

cp -au amc LICENSE MANIFEST.in README.md requirements.txt setup.py $TMPDIR

cd $TMPDIR
$PYTHON setup.py sdist
cp dist/*.tar.gz $CWD
rm -rf $TMPDIR
