#include <unistd.h>
#include <tins/tins.h>
#include <string> 
#include <ctype.h>

using namespace std;
using namespace Tins;

int main(int argc, char * argv[]) {
	int channel = 0;
	if(argc < 3){
		printf("using beacon [channel] [ssid_1] ... \n");
		return -1;
	}
	
	if(!isdigit(stoi(argv[1]))) {
		channel = stoi(argv[1]);
	}
	else {
		printf("using beacon [channel] [ssid_1] ... \n");
		return -1;
	}	


	while (true){
		RadioTap tap;

		Dot11::address_type ap="00:11:22:33:44:55";		//Access Point Mac address
		Dot11::address_type unicast="ff:ff:ff:ff:ff:ff";//Target Mac address [brodcast ff:ff:ff:ff:ff:ff]

		Dot11Beacon beacon(unicast, ap);	//set beacon frame
		beacon.addr4(ap);					//set AP MAC
		beacon.ssid(argv[2]);				//set Target Mac
		beacon.ds_parameter_set(channel);	//set channel
		
		beacon.supported_rates({ 1.0f, 5.5f, 11.0f }); //what? (only work C++11)
		tap.inner_pdu(beacon);
		
		PacketSender sender("usbwlan0");
		sender.send(tap);
		usleep(1000);
	}
}
