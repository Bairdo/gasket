#!/bin/bash

USERNAME=$1
PASSWORD=$2
echo '# Where is the control interface located? This is the default path:
ctrl_interface=/var/run/wpa_supplicant

# Who can use the WPA frontend? Replace "0" with a group name if you
#   want other users besides root to control it.
# There should be no need to chance this value for a basic configuration:
ctrl_interface_group=0

# IEEE 802.1X works with EAPOL version 2, but the version is defaults 
#   to 1 because of compatibility problems with a number of wireless
#   access points. So we explicitly set it to version 2:
eapol_version=2

# When configurhost106pass WPA-Supplicant for use on a wired network, we don’t need to
#   scan for wireless access points. See the wpa-supplicant documentation if
#   you are authenticathost106pass through 802.1x on a wireless network:
ap_scan=0

network={
key_mgmt=IEEE8021X
eap=TTLS MD5
identity="'$USERNAME'"
anonymous_identity="'$USERNAME'"
password="'$PASSWORD'"
phase1="auth=MD5"
phase2="auth=PAP password=password"
eapol_flags=0
}' > /etc/wpa_supplicant/wpa_supplicant.conf

