#!/bin/bash
$VIRTUAL_ENV
sudo cp `which python2` $VIRTUAL_ENV/bin/python2_netraw
sudo chown -R $USER. $VIRTUAL_ENV/bin/python2_netraw
sudo chmod -x,u+x $VIRTUAL_ENV/bin/python2_netraw
# for sockets and set interface
sudo setcap cap_net_admin,cap_net_raw+eip $VIRTUAL_ENV/bin/python2_netraw
# only for sockets
#sudo setcap cap_net_raw=eip $VIRTUAL_ENV/bin/python2_netraw
ln -s $VIRTUAL_ENV/bin/python2_netraw `which python`
