#include <unistd.h>
#include <tins/tins.h>
#include <string> 
#include <ctype.h>

using namespace std;
using namespace Tins;

enum {CMD, CH, SSID1, SSID2, SSID3, SSID4, SSID5, SSID6, SSID7, SSID8, SSID9, SSID10};

int main(int argc, char * argv[]) {
	int channel = 0;
	int ssid_max = argc - 2; // remove commned&channel
	int ssid = SSID1;
	int insert_ch=stoi(argv[CH]);
	if(argc < 3 && argc > SSID10){
		printf("using beacon [channel] '[ssid_1]' ... '[ssid_10]' \n");
		return -1;
	}
	
	if(!isdigit(insert_ch) || insert_ch > 14) {
		channel = insert_ch;
	}
	else {
		printf("using beacon '[channel]' [ssid_1] ... [ssid_10] \n");
		return -1;
	}	
	
	//string ap_s = "00:11:22:33:44:5";
		//how to change mac address each ssid? T^T 
	
	while (true){
		RadioTap tap;
			
		//Dot11::address_type ap=ap_s.append(to_string(ssid));
			// I guess not support type "string" T^T
		
		Dot11::address_type ap="00:11:22:33:44:55";		//Access Point Mac address
		Dot11::address_type unicast="ff:ff:ff:ff:ff:ff";//Target Mac address [brodcast ff:ff:ff:ff:ff:ff]	

		Dot11Beacon beacon(unicast, ap);	//set beacon frame
		beacon.addr4(ap);					//set AP MAC
		beacon.ssid(argv[ssid]);			//set ssid
		beacon.ds_parameter_set(channel);	//set channel
		
		beacon.supported_rates({ 1.0f, 5.5f, 11.0f }); //what is it? (only work C++11)
		tap.inner_pdu(beacon);	// may be 802.11 frame 
		
		PacketSender sender("usbwlan0");	//select network interface
		sender.send(tap);					//send pdu
		usleep(10000);

		if(ssid > ssid_max){
			ssid = SSID1;
		}
		else {
			ssid++;
		}
	}
}
