#include <tins/tins.h>
#include <map>
#include <iostream>
#include <functional>

using std::cout;
using std::endl;
using std::map;
using std::bind;

using namespace Tins;

class arp_monitor{
public:
	void run (Sniffer& sniffer);
private:
	bool callback(const PDU& pdu);

	map<IPv4Address, HWAddress<6>> address;
};

void arp_monitor::run(Sniffer& sniffer){
	sniffer.sniff_loop(
		bind(
			&arp_monitor::callback,
			this,
			std::placeholders::_1
		)
	);
};

bool arp_monitor::callback(const PDU& pdu){
	const ARP& arp = pdu.rfind_pdu<ARP>();

	if (arp.opcode() == ARP::REPLY) {
		auto iter = address.find(arp.sender_ip_addr());
		if(iter == address.end()){
			address.insert({ arp.sender_ip_addr(), arp.sender_hw_addr()});
			cout << "[Info]" << arp.sender_ip_addr() << " is at " << arp.sender_hw_addr() << std::endl;
		}
		else{
			if (arp.sender_hw_addr() != iter->second){
				cout << "[Warning]" << arp.sender_ip_addr() << " is at " << iter->second 
					<< " but also at " << arp.sender_hw_addr() << endl;
			}
		}
	}
	return true;
}

int main(int argc, char * argv[]){
	if (argc != 2){
		cout << "Usage: " << *argv << " <interface> " <<endl;
		return 1;
	}
	arp_monitor monitor;
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	config.set_filter("arp");

	try{
		Sniffer sniffer(argv[1], config);

		monitor.run(sniffer);
	}
	catch (std::exception& ex){
		std::cerr << "Error: " << ex.what() << std:: endl;
	}
}
		

