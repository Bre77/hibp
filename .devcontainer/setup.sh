/opt/splunk/bin/splunk cmd python3 -m pip install wheel
/opt/splunk/bin/splunk cmd python3 -m pip install --upgrade -t src/main/resources/splunk/lib -r src/main/resources/splunk/lib/requirements.txt --no-dependencies
yarn install --ignore-engines
yarn run build
yarn run link:app