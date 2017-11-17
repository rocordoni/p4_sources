/* -*- P4_16 -*- */
/*
 * author: Roberto Cordoni
 * email: rocordoni@gmail.com
 *
 * P4 Control program for algorithm 0.1.
 */

#include <core.p4>
#include <v1model.p4>
#include "includes/headers.p4"

#define ETHERTYPE_IPV4 0x0800
#define IP_PROTOCOLS_TCP 6
#define IP_PROTOCOLS_UDP 17
#define NTP_MODE7 7
#define NTP_REQUEST_DATA_BYTES 72 //0x48
#define MONLIST_ATTACK_THRESHOLD 0
#define NTP_GETMONLIST_CODE 0x2a
#define NTP_REQUEST 0
#define NTP_RESPONSE 1
#define ATTACK 1
#define REGISTER_COUNT 16
#define REGISTER_WIDTH 16
#define BYTES_THRESHOLD 100
#define PACKETS_THRESHOLD 10
#define TS_THRESHOLD 10000000000   //nano seconds = 10^-9


const   bit<16> TYPE_IPV4 = 0x800;
//const   bit<10> INSTANCE_COUNT = 16;

/*** NAO ESQUECER DE MUDAR OS DOIS INSTACE_COUNT ****/
#define INSTANCE_COUNT 16
#define INSTANCE_COUNT_HASH 5w16
#define MIN_HASH 5w0
#define MAX_HASH 5w16
typedef bit<32>  instance_count_t;
typedef bit<9>  egressSpec_t;
typedef bit<16> register_type_t;
typedef bit<16> counter_register_type_t;
typedef bit<48> timestamp_register_type_t;

struct metadata {
    counter_register_type_t     count_val1;
    instance_count_t            hash_val;
    bit<9>                      mapped_port;
    bit<32>                     nhop_ipv4;
    counter_register_type_t     request_count;
    counter_register_type_t     response_count;
    bit<32>                     egress_port;
    timestamp_register_type_t   old_ts;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    udp_t       udp;
    ntp_first_t ntp_first;
    ntp_mode7_t ntp_mode7;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_ntp_first;
    }

    state parse_ntp_first {
        packet.extract(hdr.ntp_first);
        transition select(hdr.ntp_first.mode) {
            NTP_MODE7 : parse_ntp_mode7;
            default: accept;
        }
    }

    state parse_ntp_mode7 {
        packet.extract(hdr.ntp_mode7);
        transition accept;
    }

}
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<counter_register_type_t>(1) ntp_counter;
    register<instance_count_t>(1) amplification_attack;
    register<counter_register_type_t>(INSTANCE_COUNT) request_counter;
    register<counter_register_type_t>(INSTANCE_COUNT) response_counter;

    action drop() {
        mark_to_drop();
    }

    action set_nhop(bit<48> nhop_dmac, bit<32> nhop_ipv4, bit<9> port) {
        hdr.ethernet.dstAddr = nhop_dmac;
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action set_dmac(macAddr_t dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

    table forward {
        key = {
            meta.nhop_ipv4 : exact;
        }
        actions = {
            set_dmac;
            drop;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }


// ******************** NTP ACTION ***********************

    // Increment count register of ntp packets
    action set_ntp_count() {
        counter_register_type_t tmp;
        ntp_counter.read(tmp, 0);
        tmp = tmp + 1;
        ntp_counter.write(0, tmp);
    }

    table set_ntp_count_table {
        actions = {
            set_ntp_count;
        }
        size = 1;
        default_action = set_ntp_count();
    }
    
    action set_amplification_attack_register() {
        amplification_attack.write(0, ATTACK);
    }

    // Table that sets a register indicating that an amplification attack ocurred
    table amplification_attack_table {
        actions = {
            set_amplification_attack_register;
        }
        size = 1;
        default_action = set_amplification_attack_register();
    }

    // Increment count register of NTP requests
    action increment_request_count() {
        instance_count_t hash_val;
        counter_register_type_t request_count;
        // Function used to calculate a hash value and store it in flow_hash
        hash(hash_val, HashAlgorithm.crc32, MIN_HASH, { hdr.ipv4.srcAddr }, MAX_HASH);
        // Copy value from register ntp_monlist_request_bytes_counter[hash_val]
        request_counter.read(request_count, hash_val);
        // Increment the value
        request_count = request_count + 1;
        // Write it back to the register
        request_counter.write(hash_val, request_count);
    }

    table increment_request_count_table {
        actions = {
            increment_request_count;
        }
        size = 1;
        default_action = increment_request_count();
    }
    
    // Increment count register of NTP response
    action increment_response_count() {
        instance_count_t hash_val;
        // Function used to calculate a hash value and store it in flow_hash
        hash(hash_val, HashAlgorithm.crc32, MIN_HASH, { hdr.ipv4.dstAddr }, MAX_HASH);
        // Copy value from response register, increment the value and write back.
        response_counter.read(meta.response_count, hash_val);
        meta.response_count = meta.response_count + 1;
        response_counter.write(hash_val, meta.response_count);
        // Put value of request counter in metadata to be able to use it in main program.
        request_counter.read(meta.request_count, hash_val);
    }

    table increment_response_count_table {
        actions = {
            increment_response_count;
        }
        size = 1;
        default_action = increment_response_count();
    }
    
    apply {
        // NTP_GET_MONLIST operations and is a valid UDP header.
        if(hdr.ntp_mode7.req_code == NTP_GETMONLIST_CODE && hdr.udp.isValid()) {
            if (hdr.ntp_first.r == NTP_REQUEST) {
                // For a request, increment request counter
                increment_request_count_table.apply();
            } else {
                // For a response: increment response counter,
                // copy req and resp counts to metadata, and
                // check if the difference between them is above threshold
                increment_response_count_table.apply();
                if (meta.response_count - meta.request_count > PACKETS_THRESHOLD) {
                    // attack!
                    amplification_attack_table.apply();
                }
            }
            // NTP MONLIST Packet counter
            set_ntp_count_table.apply();
        }
        ipv4_lpm.apply();
        forward.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
