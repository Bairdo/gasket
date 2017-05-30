#timeout 10s lynx -cmd_script=lynx_logout http://10.0.12.3/logout
timeout 10s curl http://10.0.12.3/loggedout
#cmdpid=$!
#sleep 1
#kill $cmdpid
