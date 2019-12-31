# SDN

##Develop enviornment:
Ubuntu 18.04,Python 3.6.8,Mininet,Ryu

##Building graph of the network topology:

##Strategy for installing switch rules:


##Run this program on your Ubuntu OS:
1.Check the 6653 port is not occupied because this program will use 6653 port:
sudo netstate -tunlp | grep 6653
If there is any progress,kill all:
sudo kill #ID
2.run the controller:
ryu-manager --observe-links test.py
3.run the mininet:
sudo python run_mininet.py single 3

##Close this program:
1.In terminal which is running run_mininet.py:
quit/exit
2.In a new terminal:
sudo mn -c
3.kill the progress on 6653 like above.
