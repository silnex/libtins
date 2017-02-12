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
    string bssid_;   //bssid
    string station_; //station mac
    int pwr_;    //pwr
    int rate_;   //rate
    int lost_cnt_;       //lost
    int freame_cnt;     //frames
    string probe_;   //probe
};

enum {CMD, INTERFACE};
void ap_frame();
void device_frame();
void print_ap_infos(map<string, AccessPoint>& APs);
void print_st_infos(map<string, Stations>& STs);

void get_APs_info(PDU * pdu, map<string, AccessPoint>& APs);
void get_STs_info(PDU * pdu, map<string, Stations>& STs);

int     get_PWR(RadioTap& tap);
string  get_bssid(Dot11Beacon& beacon);
int     get_channel(Dot11Beacon& beacon);
string  get_essid(Dot11Beacon& beacon);
int     get_Max_rate(Dot11Beacon& beacon);
string  get_auth_info(Dot11Beacon& beacon);
pair<string,string> get_enc_cipher(Dot11Beacon& beacon);


int main(int argc, char * argv[]){
    if(argc != 2){
        cout << "Usage qirodump <inter face>" << endl;
        return 0;
    }

    map<string, AccessPoint> APs;
    map<string, Stations> STs;

    Sniffer sniffer(static_cast<string>(argv[INTERFACE]));
    PDU * pdu = sniffer.next_packet();
    while (1){
        for(int i = 0; i<20 ; i++){
            get_APs_info(pdu, APs);
            get_STs_info(pdu, STs);
            pdu = sniffer.next_packet();
        }
        ap_frame();
        print_ap_infos(APs);
        device_frame();
        print_st_infos(STs); // 최적화 따윈 개나 주라지!
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


void print_ap_infos(map<string, AccessPoint>& APs){
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
void print_st_infos(map<string, Stations> &STs){
    for( auto& p : STs){
        auto& st = p.second;
        cout<<(left);
        cout << setw(17) << st.bssid_;
        cout << "  " <<setw(17)<< st.station_;
        cout << "  " <<setw(3)<< st.pwr_;
        cout << "  " <<setw(12)<< st.rate_;
        cout << "  " <<setw(6)<< st.lost_cnt_;
        cout << "  " <<setw(5)<< st.freame_cnt;
        cout << "  " << st.probe_ << endl;
    }
}


int     get_PWR(RadioTap& tap){
    return static_cast<int>(tap.dbm_signal());
}
string  get_bssid(Dot11Beacon& beacon){
        return beacon.addr2().to_string();

}
int     get_channel(Dot11Beacon& beacon){
    return beacon.ds_parameter_set();
}
string  get_essid(Dot11Beacon& beacon){
    return beacon.ssid();
}
int     get_Max_rate(Dot11Beacon& beacon){
    try{
    uint8_t rate0 = beacon.supported_rates().back();
    uint8_t rate1 = beacon.extended_supported_rates().back();
    return (rate0 > rate1) ? (int)rate0 : (int)rate1;
    }
    catch(option_not_found){
        return -1;
    }
}
string  get_auth_info(Dot11Beacon& beacon){
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
void    get_APs_info(PDU * pdu, map<string, AccessPoint>& APs){
    Dot11& dot11 = pdu->rfind_pdu<Dot11>();
    try {
        Dot11Beacon& beacon = pdu->rfind_pdu<Dot11Beacon>();
        AccessPoint& ap = APs[get_bssid(beacon)];

        RadioTap& tap = pdu->rfind_pdu<RadioTap>();
        ap.pwr_     = get_PWR(tap);

        ap.bssid_   = get_bssid(beacon);
        ap.channel_ = get_channel(beacon);
        ap.mb_      = get_Max_rate(beacon);
        ap.auth_    = get_auth_info(beacon);
        ap.essid_   = get_essid(beacon);

        auto temp = get_enc_cipher(beacon);    // return pair<> data
        ap.enc_     = temp.first;
        ap.cipher_  = temp.second;

        if(dot11.subtype() == Dot11::BEACON){
            ap.bc_cnt_++;   // beacon conunting
        }
        //ap.s_ = not ready;
    }
    catch(pdu_not_found&) {
        if(dot11.type() == Dot11::DATA){
            Dot11Data& data = dot11.rfind_pdu<Dot11Data>();
            if(APs.find(data.addr1().to_string()) == APs.end()){
                return; //
            }
            else {
                AccessPoint& ap = APs[data.addr1().to_string()];    // not use get_beacon
                ap.data_cnt_++;
            }
        }

    }
}
void    get_STs_info(PDU * pdu, map<string, Stations>& STs){
    Dot11& dot11 = pdu->rfind_pdu<Dot11>();
    if(dot11.subtype()!=Dot11::BEACON){
        if(dot11.subtype()==Dot11::PROBE_REQ){
            try{
                Dot11ProbeRequest& Probe = dot11.rfind_pdu<Dot11ProbeRequest>();
                Stations& st = STs[Probe.addr1().to_string()];
                st.bssid_=Probe.addr1().to_string();
                st.station_=Probe.addr2().to_string();;
                //st.probe_=Probe.ssid();
            }catch(pdu_not_found){
                return;
            }
        }
        else if (dot11.subtype()==Dot11::PROBE_RESP){
            try{
                Dot11ProbeResponse& Probe = dot11.rfind_pdu<Dot11ProbeResponse>();
                Stations& st = STs[Probe.addr1().to_string()];
                st.bssid_=Probe.addr2().to_string();
                st.station_=Probe.addr1().to_string();
                st.probe_=Probe.ssid();
            } catch (pdu_not_found){
                return;
            }
        }

    }
}


pair<string,string> get_enc_cipher(Dot11Beacon& beacon){
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
