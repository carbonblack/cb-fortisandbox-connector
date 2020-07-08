# Carbon Black - FortiSandbox Connector

The Fortisandbox connector submits binaries collected by Carbon Black to a Fortinet Fortisandbox appliance
for binary analysis. The results are collected and placed into an Intelligence
Feed on your Carbon Black server. The feed will then tag any binaries executed on your
endpoints identified as malware by Fortisandbox. Only binaries submitted by the connector
for analysis will be included in the generated Intelligence Feed.

This connector submits full binaries by default, and binaries may be shared with Fortinet based on the configuration on your Fortisandbox appliance. 

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-fortisandbox-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/fortisandbox/connector.conf.example` file to
`/etc/cb/integrations/fortisandbox/connector.conf`. Edit this file and place your Carbon Black API key into the
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

Then you must place your credentials for Fortisandbox into the configuration file: place the username 
into the `fortisandbox_username` variable, and the password into the 'fortisandbox_password' variable in the
`/etc/cb/integrations/fortisandbox/connector.conf` file.

Adjust the 'fortisandbox_url' variable in the connector configuration file to use the hostname/ip address of the Fortisandbox to be used. 

Any errors will be logged into `/var/log/cb/integrations/fortisandbox/fortisandbox.log`.

## Troubleshooting

If you suspect a problem, please first look at the Fortisandbox connector logs found here:
`/var/log/cb/integrations/fortisandbox/fortisandbox.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

1. Stop the service: `service cb-fortisandbox-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/fortisandbox/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `service cb-fortisandbox-connector start`

## Support

1. Use the [Developer Community Forum](https://community.carbonblack.com/t5/Developer-Relations/bd-p/developer-relations) to discuss issues and ideas with other API developers in the Carbon Black Community.
2. Report bugs and change requests through the GitHub issue tracker. Click on the + sign menu on the upper right of the screen and select New issue. You can also go to the Issues menu across the top of the page and click on New issue.
3. View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com/) along with reference documentation, video tutorials, and how-to guides.
