#!/bin/bash
cd "${0%/*}"
OUTPUT="${1:-hibp.spl}"
yarn install --non-interactive
yarn run build
chmod -R u=rwX,go= stage/*
chmod -R u-x+X stage/*
chmod -R u=rwx,go= stage/bin/*
mv stage hibp
python3 -m pip install --upgrade -t src/main/resources/splunk/lib -r src/main/resources/splunk/lib/requirements.txt --no-dependencies
tar -cpzf $OUTPUT --exclude=hibp/.* --overwrite hibp 
rm -rf hibp