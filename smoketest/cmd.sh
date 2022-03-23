#!/bin/bash

set -e

if [ -z "$1" ]; then
  echo Error: Missing rpm file location parameter.  Ex: ./run_smoketest.sh path/to/rpm
  exit 1
fi

RPM_FILE=$(find "$1" -name "*.rpm" -print -quit)

SYSTEM_CTL_PATCH="https://${ARTIFACTORY_SERVER}/artifactory/cb/gdraheim/docker-systemctl-replacement/1.4.3424/systemctl.py"
if [[ "$(cat /etc/redhat-release)" == *"release 8"* ]]; then
  SYSTEM_CTL_PATCH="https://${ARTIFACTORY_SERVER}/artifactory/cb/gdraheim/docker-systemctl-replacement/1.4.3424/systemctl3.py"
fi

echo Adding cb user
groupadd cb --gid 8300 && \
useradd --shell /sbin/nologin --gid cb --comment "Service account for VMware Carbon Black EDR" -M cb

echo Running smoke test on file: "$RPM_FILE"

rpm -ivh "$RPM_FILE"

cp $2/connector.conf /etc/cb/integrations/fortisandbox/connector.conf
cd $2/../test ; FLASK_APP=smoke_test_server.py python3.8 -m flask run --cert=adhoc &
echo Starting service...
service cb-fortisandbox-connector start
sleep 10
grep "Analyzed md5sum:" /var/log/cb/integrations/fortisandbox/fortisandbox.log >/dev/null
if [ $? -eq 1 ]
then
  echo "Fortisandbox not working correctly"
  exit 1
else
  echo "Fortisandbox working correctly"
fi
service cb-fortisandbox-connector stop
yum -y remove python-cb-fortisandbox-connector
