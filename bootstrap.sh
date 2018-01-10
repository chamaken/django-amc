#!/bin/sh
# https://stackoverflow.com/questions/4324558/whats-the-proper-way-to-install-pip-virtualenv-and-distribute-for-python

INITIAL_ENV=${1:-venv}
PYTHON=$(which python3 || which python)

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR virtualenv.tar.gz" 1 2 15

curl -Lo virtualenv.tar.gz 'https://github.com/pypa/virtualenv/tarball/master'
tar xzf virtualenv.tar.gz -C $TMPDIR --strip-components=1
$PYTHON $TMPDIR/virtualenv.py $INITIAL_ENV
rm -rf $TMPDIR
$INITIAL_ENV/bin/pip install virtualenv.tar.gz
rm -f virtualenv.tar.gz

. $INITIAL_ENV/bin/activate
cat <<EOF | pip install -r /dev/stdin
Django >=1.11,<2.0
EOF
deactivate
