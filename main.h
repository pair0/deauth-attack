#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/in.h>
#include <unistd.h>
#include "mac.h"

struct Radiotap_header { //24
    u_int8_t    revision;
    u_int8_t    pad;
    u_int16_t   length;
    u_int32_t   Present_flags;
};

struct Deauthentication{
    u_int16_t type;
    u_int16_t duration;
    Mac dst_addr;
    Mac src_addr;
    Mac BSSID;
    u_int16_t number;

    Mac dmac() { return dst_addr; }
	Mac smac() { return src_addr; }
    Mac bssid() { return BSSID; }
};

struct Wireless{
    u_int16_t reason_code;
};

struct Deauth{
    Radiotap_header radiotap;
    Deauthentication deauthentication;
    Wireless wireless;
};