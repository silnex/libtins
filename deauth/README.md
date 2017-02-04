#Deauth Packet Sender
This program is disconneting to Device from AP 

#How To Use?
This program need libtins library and monitor mode wireless lan card

compile deauth.cpp
g++ -std=c++11 -o deauth.o deauth.cpp -ltins

./deauth.o <interface> <ap mac address> [<deivce mac address>]
