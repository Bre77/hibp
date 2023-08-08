mv stage stage2
node bin/build.js build
mv stage hibp
mv stage2 stage
chmod -R u=rwX,go= hibp/*
chmod -R u-x+X hibp/*
chmod -R u=rwx,go= hibp/bin/*
rm $1
tar -cpzf $1 --exclude=hibp/.* --exclude=hibp/local hibp
rm -rf hibp