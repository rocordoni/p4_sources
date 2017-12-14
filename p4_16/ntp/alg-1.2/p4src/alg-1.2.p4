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
#define NTP_REQUEST_DATA_BYTES 8
#define MONLIST_ATTACK_THRESHOLD 0
#define NTP_GETMONLIST_CODE 0x2a
#define NTP_REQUEST 0
#define NTP_RESPONSE 1
#define ATTACK 1
#define BYTES_THRESHOLD 50000
#define TS_THRESHOLD 1000000 // micro seconds = 10^-6


const   bit<16> TYPE_IPV4 = 0x800;

/*** NAO ESQUECER DE MUDAR OS DOIS INSTACE_COUNT ****/
#define INSTANCE_COUNT 2
#define MIN_HASH 5w0
#define MAX_HASH 5w2
typedef bit<32>  instance_count_t;
typedef bit<9>  egressSpec_t;
typedef bit<16> register_type_t;
typedef bit<32> counter_register_type_t;
typedef bit<48> timestamp_register_type_t;

struct metadata {
    bit<32>                     nhop_ipv4;
    instance_count_t            hash_val;
    counter_register_type_t     request_bytes;
    counter_register_type_t     response_bytes;
    counter_register_type_t     curr_num_attacks;
    timestamp_register_type_t   old_ts;
    timestamp_register_type_t   curr_ts;
    timestamp_register_type_t   attack_timestamp;
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    udp_t       udp;
    ntp_first_t ntp_first;
    ntp_mode7_t ntp_mode7;
    ntp_mode7_data_t ntp_mode7_data;
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
        transition parse_ntp_mode7_data;
    }

    state parse_ntp_mode7_data {
        packet.extract(hdr.ntp_mode7_data, (bit<32>)(hdr.ntp_mode7.n_data_items * hdr.ntp_mode7.size_data_item));
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
    register<counter_register_type_t>(INSTANCE_COUNT) amplification_attack;
    register<timestamp_register_type_t>(INSTANCE_COUNT) amplification_attack_timestamp;
    register<timestamp_register_type_t>(1) diff_ts_reg;
    register<counter_register_type_t>(INSTANCE_COUNT) ntp_monlist_request_bytes_counter;
    register<counter_register_type_t>(INSTANCE_COUNT) ntp_monlist_response_bytes_counter;
    register<timestamp_register_type_t>(INSTANCE_COUNT) response_ts;

    action drop() {
        mark_to_drop();
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
        amplification_attack.read(meta.curr_num_attacks, meta.hash_val);
        amplification_attack_timestamp.read(meta.attack_timestamp, meta.hash_val);
        meta.curr_num_attacks = meta.curr_num_attacks + 1;
        meta.attack_timestamp = standard_metadata.ingress_global_timestamp;

        amplification_attack.write(meta.hash_val, meta.curr_num_attacks);
        amplification_attack_timestamp.write(meta.hash_val, meta.attack_timestamp);
        ntp_monlist_request_bytes_counter.write(meta.hash_val, 0);
        ntp_monlist_response_bytes_counter.write(meta.hash_val, 0);
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
        // Function used to calculate a hash value and store it in hash_val
        hash(meta.hash_val, HashAlgorithm.crc32, MIN_HASH, { hdr.ipv4.srcAddr }, MAX_HASH);
        // Copy value from register ntp_monlist_request_bytes_counter[hash_val]
        ntp_monlist_request_bytes_counter.read(meta.request_bytes, meta.hash_val);
        // Increment the value
        meta.request_bytes = meta.request_bytes + NTP_REQUEST_DATA_BYTES;
        // Write it back to the register
        ntp_monlist_request_bytes_counter.write(meta.hash_val, meta.request_bytes);
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
        // Function used to calculate a hash value and store it in hash_val
        hash(meta.hash_val, HashAlgorithm.crc32, MIN_HASH, { hdr.ipv4.dstAddr }, MAX_HASH);
        // We need to get request bytes in order to calculate the difference between response and request
        ntp_monlist_request_bytes_counter.read(meta.request_bytes, meta.hash_val);
        // Copy value from register ntp_monlist_response_bytes_counter[hash_val]
        ntp_monlist_response_bytes_counter.read(meta.response_bytes, meta.hash_val);
        // Increment and write it back to register
        meta.response_bytes = meta.response_bytes + (counter_register_type_t)(hdr.ntp_mode7.n_data_items * hdr.ntp_mode7.size_data_item);
        ntp_monlist_response_bytes_counter.write(meta.hash_val, meta.response_bytes);
    }

    table set_ntp_monlist_response_count_table {
        actions = {
            set_ntp_monlist_response_count;
        }
        size = 1;
        default_action = set_ntp_monlist_response_count();
    }

    // Set response timestamp with the new value
    action get_set_response_TS() {
        // Function used to calculate a hash value and store it in hash_val
        hash(meta.hash_val, HashAlgorithm.crc32, MIN_HASH, { hdr.ipv4.dstAddr }, MAX_HASH);
        // Get and Update time stamp
        meta.curr_ts = standard_metadata.ingress_global_timestamp;
        response_ts.read(meta.old_ts, meta.hash_val);
        response_ts.write(meta.hash_val, meta.curr_ts);
        diff_ts_reg.write(0, meta.curr_ts - meta.old_ts); //debug
    }

    table get_set_response_TS_table {
        actions = {
            get_set_response_TS;
        }
        size = 1;
        default_action = get_set_response_TS();
    }


    // Reset timestamp and bytes
    action reset_bytes() {
        hash(meta.hash_val, HashAlgorithm.crc32, MIN_HASH, { hdr.ipv4.dstAddr }, MAX_HASH);
        // Reset values
        ntp_monlist_request_bytes_counter.write(meta.hash_val, 0);
        ntp_monlist_response_bytes_counter.write(meta.hash_val, 0);
    }

    table reset_bytes_table {
        actions = {
            reset_bytes;
        }
        size = 1;
        default_action = reset_bytes();
    }

    apply {
        /* NTP_GET_MONLIST operations and valid UDP header */
        if(hdr.ntp_mode7.req_code == NTP_GETMONLIST_CODE && hdr.udp.isValid()) {
            if (hdr.ntp_first.r == NTP_REQUEST) {
                /* Update request bytes and copy bytes registers to metadata */
                set_ntp_monlist_request_count_table.apply();
            } else if (hdr.ntp_first.r == NTP_RESPONSE) {
                /* Update response bytes and copy bytes registers to metadata */
                set_ntp_monlist_response_count_table.apply();
                get_set_response_TS_table.apply();
                /* If new_timestamp - old_timestamp is lower than threshold: check for bytes */
                if (meta.curr_ts - meta.old_ts < TS_THRESHOLD) {
                    /* Check for Amplification attack */
                    if (meta.response_bytes - meta.request_bytes > BYTES_THRESHOLD) {
                        amplification_attack_table.apply();
                    }
                } else {
                    /* Two responses for same index came far apart from each other. This may not be an attack.
                       Reset timestamp and bytes */
                    reset_bytes_table.apply();
                }
            }
            set_ntp_count_table.apply();
        }
        ipv4_lpm.apply();
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
        packet.emit(hdr.udp);
        packet.emit(hdr.ntp_first);
        packet.emit(hdr.ntp_mode7);
        packet.emit(hdr.ntp_mode7_data);
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
