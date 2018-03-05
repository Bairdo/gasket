#!/bin/sh

IFNAME=$1
CMD=$2

echo "$IFNAME $CMD " >> /tmp/abcd.defg
if [ "$CMD" = "CONNECTED" ]; then
    echo "CCCCC" >> /tmp/abcd.defg
    sleep 5;
    wpa_cli -i$IFNAME logoff;
    sleep 10;
    wpa_cli -i$IFNAME logon;
fi

if [ "$CMD" = "DISCONNECTED" ]; then

    echo "dddd" >> /tmp/abcd.defg
    sed -i 's/logoff/status/g' $0;
    sleep 5;
#    wpa_cli -i$IFNAME logon;
fi

