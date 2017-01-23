#include <iostream>
#include <set>
#include <string>
#include <tins/tins.h>

using std::set;
using std::cout;
using std::endl;
using std::string;
using std::runtime_error;

using namespace Tins;

class BeaconSniffer{
public:
	void run (const string & iface);
private:
	typedef Dot11::address_type address_type;
	typedef set<address_type> ssids_type;

	bool callback(PDU & pdu);

	ssids_type ssids;
};

void BeaconSniffer::run(const std::string & iface){
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	config.set_filter("type mgt subtype beacon");
	config.set_rfmon(true);
	Sniffer sniffer(iface, config);
	sniffer.sniff_loop(make_sniffer_handler(this, &BeaconSniffer::callback));
}

bool BeaconSniffer::callback (PDU & pdu){
	const Dot11Beacon& beacon = pdu.rfind_pdu<Dot11Beacon>();
	
	if(!beacon.from_ds() && !beacon.to_ds()){
		address_type addr = beacon.addr2();

		ssids_type::iterator it = ssids.find(addr);

		if(it == ssids.end()){
			try{
				string ssid = beacon.ssid();
				ssids.insert(addr);
				
				cout << addr << "\t" << (int)beacon.ds_parameter_set() << "\t" <<ssid << endl;
			}
			catch(runtime_error&){

			}
		}
	}
	return true;
}


int main (int argc, char * argv[]){
	if (argc != 2){
		cout << "Usage: " << * argv << " <interface> " <<endl;
		return 1;
	}
	
	string interface = argv[1];
	BeaconSniffer sniffer;
	system("clear");
	cout << "BSSID\t\t\tCH\tESSID" << endl;
	sniffer.run(interface);

}
