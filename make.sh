mv stage stage2
node bin/build.js build
mv stage badrcm
mv stage2 stage
chmod -R u=rwX,go= badrcm/*
chmod -R u-x+X badrcm/*
chmod -R u=rwx,go= badrcm/bin/*
rm $1
tar -cpzf $1 --exclude=badrcm/.* --exclude=badrcm/local badrcm
rm -rf badrcm