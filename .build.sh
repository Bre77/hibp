#!/bin/bash
cd "${0%/*}"
OUTPUT="${1:-hibp.spl}"
yarn install --non-interactive
yarn run build
chmod -R u=rwX,go= stage/*
chmod -R u-x+X stage/*
chmod -R u=rwx,go= stage/bin/*
mv stage hibp
python3 -m pip install --upgrade -t hibp/lib -r hibp/lib/requirements.txt --no-dependencies
rm -rf hibp/lib/splunklib/__pycache__
rm -rf hibp/lib/splunklib/searchcommands/__pycache__
rm -rf hibp/lib/splunklib/modularinput/__pycache__
rm -rf hibp/lib/*/__pycache__
tar -cpzf $OUTPUT --exclude=hibp/.* --overwrite hibp 
rm -rf hibp