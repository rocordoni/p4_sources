/* -*- P4_16 -*- */
/*
 * author: Roberto Cordoni
 * email: rocordoni@gmail.com
 *
 * P4 Control program for algorithm 1.1.
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


const   bit<16> TYPE_IPV4 = 0x800;
//const   bit<10> INSTANCE_COUNT = 16;

/*** NAO ESQUECER DE MUDAR OS DOIS INSTACE_COUNT ****/
#define INSTANCE_COUNT 16
#define INSTANCE_COUNT_HASH 10w16
typedef bit<32>  instance_count_t;

typedef bit<9>  egressSpec_t;
typedef bit<16> register_type_t;
typedef bit<16> counter_register_type_t;

struct metadata {
    counter_register_type_t     count_val1;
    instance_count_t            hash_val;
    bit<9>                      mapped_port;
    bit<32>                     nhop_ipv4;
    counter_register_type_t     request_bytes;
    counter_register_type_t     response_bytes;
    bit<32>                     egress_port;
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

    register<register_type_t>(1) spoofed_pkts_reg;
    register<egressSpec_t>(1) mapped_port_reg;
    register<counter_register_type_t>(1) ntp_counter;
    register<counter_register_type_t>(1) amplification_attack;
    register<counter_register_type_t>(INSTANCE_COUNT) ntp_monlist_request_bytes_counter;
    register<counter_register_type_t>(INSTANCE_COUNT) ntp_monlist_response_bytes_counter;

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

    action get_mapped_port(bit<9> port) {
        mapped_port_reg.write(0, port);
        meta.mapped_port = port;
    }

    table mapped_port {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            get_mapped_port;
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
    
    action set_spoof_register() {
        counter_register_type_t tmp;
        spoofed_pkts_reg.read(tmp, 0);
        tmp = tmp + 1;
        spoofed_pkts_reg.write(0, tmp);
    }

    // Table that sets a register indicating that an attack ocurred
    table spoof_table {
        actions = {
            set_spoof_register;
        }
        size = 1;
        default_action = set_spoof_register();
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
    action set_ntp_monlist_request_count() {
        instance_count_t hash_val;
        counter_register_type_t response_bytes;
        counter_register_type_t request_bytes;
        // Function used to calculate a hash value and store it in flow_hash
        hash(hash_val, HashAlgorithm.crc16, 10w0, { hdr.ipv4.srcAddr }, INSTANCE_COUNT_HASH);
        // We need to get response bytes in order to calculate the difference between response and request
        ntp_monlist_response_bytes_counter.read(meta.response_bytes, hash_val);
        // Copy value from register ntp_monlist_request_bytes_counter[hash_val]
        // to custom_ntp_metadata.request_bytes
        ntp_monlist_request_bytes_counter.read(request_bytes, hash_val);
        // Increment the value
        request_bytes = request_bytes + NTP_REQUEST_DATA_BYTES;
        // Write it back to the register
        ntp_monlist_request_bytes_counter.write(hash_val, request_bytes);
    }

    table set_ntp_monlist_request_count_table {
        actions = {
            set_ntp_monlist_request_count;
        }
        size = 1;
        default_action = set_ntp_monlist_request_count();
    }

    // Increment count register of NTP responses
    action set_ntp_monlist_response_count() {
        instance_count_t hash_val;
        counter_register_type_t response_bytes;
        counter_register_type_t request_bytes;
        // Function used to calculate a hash value and store it in hash_val
        hash(hash_val, HashAlgorithm.crc16, 10w0, { hdr.ipv4.dstAddr }, INSTANCE_COUNT_HASH);
        // We need to get request bytes in order to calculate the difference between response and request
        ntp_monlist_request_bytes_counter.read(meta.request_bytes, hash_val);
        // Copy value from register ntp_monlist_response_bytes_counter[hash_val]
        ntp_monlist_response_bytes_counter.read(response_bytes, hash_val);
        // Increment and write it back to register
        response_bytes = response_bytes + (bit<16>)(hdr.ntp_mode7.n_data_items * hdr.ntp_mode7.size_data_item);
        ntp_monlist_response_bytes_counter.write(hash_val, response_bytes);
    }

    table set_ntp_monlist_response_count_table {
        actions = {
            set_ntp_monlist_response_count;
        }
        size = 1;
        default_action = set_ntp_monlist_response_count();
    }

    apply {
        /* Copy the port from switch_table to meta.egress */
        mapped_port.apply();
        /* NTP_GET_MONLIST operations and valid UDP header */
        if(hdr.ntp_mode7.req_code == NTP_GETMONLIST_CODE && hdr.udp.isValid()) {
            if (hdr.ntp_first.r == NTP_REQUEST) {
                set_ntp_monlist_request_count_table.apply();
                if (meta.mapped_port != standard_metadata.ingress_port) {
                    //Spoofing
                    spoof_table.apply();
                }
            } else if (hdr.ntp_first.r == NTP_RESPONSE) {
                set_ntp_monlist_response_count_table.apply();
                if (meta.response_bytes - meta.request_bytes > BYTES_THRESHOLD) {
                    amplification_attack_table.apply();
                }
            }
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

