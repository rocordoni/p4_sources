/* -*- P4_16 -*- */
/*
 * author: Roberto Cordoni
 * email: rocordoni@gmail.com
 *
 * Headers definition.
 */

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header ntp_first_t {
    bit<1>  r;
    bit<1>  m;
    bit<3>  version;
    bit<3>  mode;
}

header ntp_mode7_t {
    bit<1>  a;
    bit<7>  sequence;
    bit<8>  implementation;
    bit<8>  req_code;
    bit<4>  err;
    bit<12> n_data_items;
    bit<4>  mbz;
    bit<12> size_data_item;
}

header ntp_mode7_data_t {
    varbit<32> data;
}

//header_type dns_t {
    //fields {
        //id              : 16;
        //qr              : 1;
        //opcode          : 4;
        //aa              : 1;
        //tc              : 1;
        //rd              : 1;
        //ra              : 1;
        //z               : 1;
        //ad              : 1;
        //cd              : 1;
        //rcode           : 4;
        //tot_questions   : 16;
        //tot_answ_rr     : 16;
        //tot_auth_rr     : 16;
        //tot_add_rr      : 16;
    //}
//}

