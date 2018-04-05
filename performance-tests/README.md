# 'Performance Tests'

Eventually the goal of these tests is to compare implementations of 802.1X systems.



| Test Name       |   metrics |
| --------------- | --------- |
| Test3           | auth_time, logoff_time, reauth_time |
| test_many_hosts | auth_times, logoff_times, reauth_times for more than one host. |



If there is an error when running the tests, it may be necessary to remove the ovs-bridge and shutdown the Docker containers manually.

```bash
ovs-vsctl del-br s1
docker ps
docker stop performancetests_gasket_1
docker stop performancetests_faucet_1
...
```


## Run


```bash
python2 tests.py -p <directoy to save all pcaps> <number of runs> --num-hosts <list of number of hosts to use>
```
E.g. to run the tests with the 1,2,3,4,5 hosts and 50 runs each.
```bash
export FAUCET_EVENT_SOCK=/var/run/faucet/faucet.sock
export FA_RABBIT_HOST=172.122.0.104
python2 tests.py -p pcaps 50 --num-hosts 1 2 3 4 5
```