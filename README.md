# SDN

## Develop enviornment:
Ubuntu 18.04,Python 3.6.8,Mininet,Ryu

## Building graph of the network topology:

## Strategy for installing switch rules:


## Run this program on your Ubuntu OS:
1.Check the 6653 port is not occupied because this program will use 6653 port:<br>
sudo netstate -tunlp | grep 6653<br>
If there is any progress,kill all:<br>
sudo kill #ID<br>
2.run the controller:<br>
ryu-manager --observe-links test.py<br>
3.run the mininet:<br>
sudo python run_mininet.py single 3<br>

## Close this program:
1.In terminal which is running run_mininet.py:<br>
quit/exit<br>
2.In a new terminal:<br>
sudo mn -c<br>
3.kill the progress on 6653 like above.<br>
