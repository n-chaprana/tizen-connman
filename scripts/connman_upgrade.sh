#!/bin/sh
PATH=/bin:/usr/bin:/sbin:/usr/sbin

#-----------------------------------------------#
# connman patch script for upgrade (2.4 -> 3.0) #
#-----------------------------------------------#

#/%{_localstatedir} = /opt/var

chsmack -a 'System' /opt/var/lib/connman
chsmack -a 'System' /opt/var/lib/connman/settings

