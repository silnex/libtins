#include <tins/tins.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unistd.h>
using namespace std;
using namespace Tins;

struct AccessPoint{
    string bssid_;  //bssid
    int pwr_;    //pwr
    unsigned int bc_cnt_ = 0; //beacon
    unsigned int data_cnt_ = 0;//#data
    unsigned int s_ = 0; //#/s
    int channel_;    //ch
    int mb_;//mb
    string enc_;     //ENC
    string cipher_;   //CIPHER
    string auth_;    //AUTH
    string essid_;   //ESSID
};

struct Stations{
    string bssid;   //bssid
    string station; //station mac
    int pwr;    //pwr
    //rate
    int lost;       //lost
    int freame;     //frames
    string probe;   //probe
};

enum {CMD, INTERFACE};
void ap_frame();
void device_frame();
void ap_infos(map<string, AccessPoint>& APs);

void get_APs_info(PDU * pdu, map<string, AccessPoint>& APs);

int find_Max_rate(Dot11Beacon& beacon);

pair<string,string> find_enc_cipher(Dot11Beacon& beacon);
string find_auth(Dot11Beacon& beacon);

int main(int argc, char * argv[]){
    if(argc != 2){
        cout << "Usage qirodump <inter face>" << endl;
        return 0;
    }

    map<string, AccessPoint> APs;

    Sniffer sniffer(static_cast<string>(argv[INTERFACE]));
    PDU * pdu = sniffer.next_packet();
    while (1){
        for(int i = 0; i<20 ; i++){
            get_APs_info(pdu, APs);
            pdu = sniffer.next_packet();
        }
        ap_frame();
        ap_infos(APs);
        device_frame();
        sleep(1);
        system("clear");
    }
    return 0;
}
void ap_frame() {
    cout<<(left);
    cout<<setw(17)<<"BSSID";
    cout<<"  "<<setw(3)<<"PWR";
    cout<<"  "<<setw(7)<<"Beacons";
    cout<<"  "<<setw(7)<<"#Data,";
    cout<<"  "<<setw(2)<<"CH";
    cout<<"  "<<setw(4)<<"MB";
    cout<<"  "<<setw(4)<<"ENC";
    cout<<"  "<<setw(6)<<"CIPHER";
    cout<<"  "<<setw(4)<<"AUTH";
    cout<<"  "<<"ESSID"<<endl;
}

void device_frame() {
    cout<<(left);
    cout<<setw(17)<<"BSSID";
    cout<<"  "<<setw(17)<<"STATION";
    cout<<"  "<<setw(5)<<"PWR";
    cout<<"  "<<setw(10)<<"Rate";
    cout<<"  "<<setw(5)<<"Lost";
    cout<<"  "<<setw(6)<<"Frames";
    cout<<"  "<<"Probe"<<endl;
}

void ap_infos(map<string, AccessPoint>& APs){
    for( auto& p : APs){
        auto& ap = p.second;
        cout<<(left);
        cout << setw(17) << ap.bssid_;
        cout << "  " <<setw(3)<< ap.pwr_;
        cout << "  " <<setw(7)<< ap.bc_cnt_;
        cout << "  " <<setw(7)<< ap.data_cnt_;
        cout << "  " <<setw(2)<< ap.channel_;
        cout << "  " <<setw(4)<< ap.mb_;
        cout << "  " <<setw(4)<< ap.enc_;
        cout << "  " <<setw(6)<< ap.cipher_;
        cout << "  " <<setw(4)<< ap.auth_;
        cout << "  " << ap.essid_ << endl;
    }
}

void get_APs_info(PDU * pdu, map<string, AccessPoint>& APs){
    RadioTap &tap = pdu->rfind_pdu<RadioTap>();
    Dot11& dot11 = pdu->rfind_pdu<Dot11>();
    try {
        Dot11Beacon& beacon = pdu->rfind_pdu<Dot11Beacon>();
        string bssid = beacon.addr2().to_string();
        AccessPoint& ap = APs[bssid];

        ap.bssid_   = bssid;  // insert bssid
        ap.pwr_     = static_cast<int>(tap.dbm_signal());
        ap.channel_ = beacon.ds_parameter_set();
        ap.mb_      = find_Max_rate(beacon);
            auto temp = find_enc_cipher(beacon);
        ap.enc_     = temp.first;
        ap.cipher_  = temp.second;
        ap.auth_    = find_auth(beacon);
        ap.essid_   = beacon.ssid();

        if (dot11.type() == Dot11::MANAGEMENT){
            if(dot11.subtype() == Dot11::BEACON){
                ap.bc_cnt_++;
            }
        }
        //ap.s_ = not ready;
    } catch(pdu_not_found&) {
        if(dot11.type() == Dot11::DATA){
            Dot11Data& data = dot11.rfind_pdu<Dot11Data>();
            if(APs.find(data.addr1().to_string()) == APs.end()){
                return;
            }else{
                AccessPoint& ap = APs[data.addr1().to_string()];
                ap.data_cnt_++;
            }

        }

    }
}

int find_Max_rate(Dot11Beacon& beacon){
    uint8_t rate0 = beacon.supported_rates().back();
    uint8_t rate1 = beacon.extended_supported_rates().back();

    return (rate0 > rate1) ? (int)rate0 : (int)rate1;
}

string find_auth(Dot11Beacon& beacon){
    try{
        if(beacon.rsn_information().akm_cyphers()[0] == RSNInformation::PSK){
            return "PSK";
        } else if (beacon.rsn_information().akm_cyphers()[0] == RSNInformation::PMKSA){
            return "MGT";
        }
    }
    catch(option_not_found&){
        return "   ";
    }
    return "   ";
}

pair<string,string> find_enc_cipher(Dot11Beacon& beacon){
    string cipher, enc;
    if(!beacon.capabilities().privacy()){
        enc="OPN";
        cipher = "   ";
    }else{
        try{
            // WPA2
            auto RSN = beacon.rsn_information().pairwise_cyphers()[0];
            enc = "WPA2";
            if(RSN == RSNInformation::CCMP){
                cipher = "CCMP";
            }else if (RSN == RSNInformation::TKIP){
                cipher = "TKIP";
            }else if (RSN == RSNInformation::WEP_40){
                cipher = "WEP";
            }else{
                cipher = "WEP_104";
            }
        }
        catch(option_not_found&){
            //WEP or WPA
            enc = "WEA";
            cipher = "WEA";
        }
    }
    return pair<string,string>(enc,cipher);
}

