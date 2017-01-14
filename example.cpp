#include <tins/tins.h>

using namespace Tins;

int main() {
	EthernetII eth;
	IP *ip = new IP();
	TCP *tcp = new TCP();
	// tcp is ip's inner pdu
	ip->inner_pdu(tcp);
	// ip is eth's inner pdu
	eth.inner_pdu(ip);
}
//g++ example.cpp -o example -O3 -std=c++11 -lpthread -ltins
