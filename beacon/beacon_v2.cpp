#include <unistd.h>
#include <tins/tins.h>
#include <string> 
#include <ctype.h>
#include <iostream>

using namespace std;
using namespace Tins;

enum {CMD, CH, SSID};

int main(int argc, char * argv[]) {
	int channel = 0;
	int ssid_num = argc - SSID;	// remove commned&channel
	int next_ssid = 0;
	int now_ssid=SSID;
	int insert_ch=stoi(argv[CH]);
	string s_bssid;			// source bssid
	string d_bssid;			// destination bssid

	if(argc < 3){			// check arguments
		printf("using beacon [channel] [ssid_1] ... \n");
		return -1;
	}				// ckeck channel
	else if(isdigit(insert_ch) || 13 < insert_ch || insert_ch < 1) {	
		printf("[channel] is number and 1~13 \n");
		return -1;
	}
	else {
		channel = insert_ch;
	}

	while (true){
		RadioTap tap;

		if(ssid_num < 10){			//need change int to hex
			s_bssid = "00:11:22:33:44:5";
			s_bssid = s_bssid+to_string(next_ssid);
		}
		else if (ssid_num < 100) {		//need change int to hex
			s_bssid = "00:11:22:33:44:";
			s_bssid = s_bssid+to_string(next_ssid);
		}
		else{
			printf("to many ssids!");
		}
		
		d_bssid = "ff:ff:ff:ff:ff:ff";
		
		Dot11Beacon beacon;			//set beacon frame
		beacon.addr1(d_bssid);			//set destination ssid
		beacon.addr2(s_bssid);			//set beacon bssid
		beacon.addr3(beacon.addr2());		//set beacon bssid
		
		beacon.ssid(argv[now_ssid]);		//set ssid
		beacon.ds_parameter_set(channel);	//set channel

		beacon.supported_rates({ 1.0f, 5.5f, 11.0f }); //what is it? (only work C++11)
		tap.inner_pdu(beacon);	// may be 802.11 frame 
		
		PacketSender sender("usbwlan0");	//select network interface
		sender.send(tap);			//send pdu
		usleep(1000);

		(now_ssid > argc - 2)?( next_ssid = 0; ):( next_ssid++; )
							//test not yet
		now_ssid=SSID+next_ssid;
	}
}
