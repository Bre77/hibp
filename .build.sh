#!/bin/bash
cd "${0%/*}"
OUTPUT="${1:-hibp.spl}"
yarn install --non-interactive
yarn run build
chmod -R u=rwX,go= stage/*
chmod -R u-x+X stage/*
chmod -R u=rwx,go= stage/bin/*
mv stage hibp
tar -cpzf $OUTPUT --exclude=hibp/.* --overwrite hibp 
rm -rf hibp