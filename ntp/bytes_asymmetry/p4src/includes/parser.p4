/*
 * author: Roberto Cordoni
 * email: rocordoni@gmail.com
 *
 * P4 NTP mode7 Parser.
 */

#define ETHERTYPE_IPV4 0x0800
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define NTP_MODE7 7

parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

// Check protocol field to choose next header to parse.
parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        IP_PROTOCOLS_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
        default: ingress;
    }
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    return ingress;
}

header udp_t udp;

parser parse_udp {
    extract(udp);
    return parse_ntp_first;
}

// I choose to split NTP header in two different headers.
// As I am interested only in NTP mode7 segments (NTP MONLIST),
// I first parse untill the 'mode' field. If it's a mode7 message,
// parse the rest of the NTP header. Otherwise, go to ingress.
header ntp_first_t ntp_first;

parser parse_ntp_first {
    extract(ntp_first);
    return select(latest.mode) {
        NTP_MODE7 : parse_ntp_mode7;
        default: ingress;
    }
}

header ntp_mode7_t ntp_mode7;

parser parse_ntp_mode7 {
    extract(ntp_mode7);
    return ingress;
}



