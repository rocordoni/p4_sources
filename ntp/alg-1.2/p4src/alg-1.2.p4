/*
 * author: Roberto Cordoni
 * email: rocordoni@gmail.com
 *
 * P4 Control program for algorithm 1.1.
 */

#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/intrinsic.p4"

#define INSTANCE_COUNT 8
#define MONLIST_ATTACK_THRESHOLD 0
#define NTP_GETMONLIST_CODE 0x2a
#define NTP_REQUEST 0
#define NTP_RESPONSE 1
#define NTP_REQUEST_DATA_BYTES 72 //0x48
#define ATTACK 1
#define REGISTER_WIDTH 16
#define BYTES_THRESHOLD 100
#define TS_THRESHOLD 10000000000   //nano seconds = 10^-9

header_type custom_ntp_metadata_t {
    fields {
        hash_val: INSTANCE_COUNT;
        request_bytes: 32;
        response_bytes: 32;
        response_ts  : 64;
        egress_port: 8;
        count_val1: 16;
    }
}

header_type custom_metadata_t {
    fields {
        nhop_ipv4: 32;
    }
}


// The index for registers is the 'Client' of the NTP Client/Server model.
// So, for requests, the Client is the scrAddr
// And for responses, it is the dstAddr
field_list fields_hash_ntp_request {
    ipv4.srcAddr;
}

field_list fields_hash_ntp_response {
    ipv4.dstAddr;
}

// Using crc16 for the hash functions
field_list_calculation ntp_hash_request {
    input {
        fields_hash_ntp_request;
    }
    algorithm : crc16;
    output_width : 16;
}

field_list_calculation ntp_hash_response {
    input {
        fields_hash_ntp_response;
    }
    algorithm : crc16;
    output_width : 16;
}

// Instantiate metadata
metadata custom_metadata_t custom_metadata;
metadata custom_ntp_metadata_t custom_ntp_metadata;
metadata intrinsic_metadata_t intrinsic_metadata;

register test{
    width : 48;
    instance_count : 1;
}

register amplification_attack{
    width : REGISTER_WIDTH;
    instance_count : 1;
}

register spoofing_attack{
    width : REGISTER_WIDTH;
    instance_count : 1;
}

register ntp_counter{
    width : REGISTER_WIDTH;
    instance_count : 1;
}

register TSResponse{
    width : 64;
    instance_count : INSTANCE_COUNT;
}

register ntp_monlist_request_bytes_counter{
    width : REGISTER_WIDTH;
    instance_count : INSTANCE_COUNT;
}

register ntp_monlist_response_bytes_counter{
    width : REGISTER_WIDTH;
    instance_count : INSTANCE_COUNT;
}

action _drop() {
    drop();
}

action set_nhop(nhop_ipv4, port) {
    modify_field(custom_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

action set_egress_port(port) {
    modify_field(custom_ntp_metadata.egress_port, port);
}

table egress_port {
    reads {
        ipv4.srcAddr : lpm;
    }
    actions {
        set_egress_port;
        _drop;
    }
    size: 1024;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

table forward {
    reads {
        custom_metadata.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}


// ******************** NTP ACTION ***********************


// Increment count register of ntp packets
action set_ntp_count() {
    register_read(custom_ntp_metadata.count_val1, ntp_counter, 0);
    add_to_field(custom_ntp_metadata.count_val1, 1);
    register_write(ntp_counter, 0, custom_ntp_metadata.count_val1);
}

table set_ntp_count_table {
    actions {
        set_ntp_count;
    }
    size: 1;
}

action set_amplification_attack_register() {
    register_write(amplification_attack,
                   0,
                   ATTACK);
    register_write(test,
                   0,
                   intrinsic_metadata.ingress_global_timestamp - custom_ntp_metadata.response_ts);
}

// Table that sets a register indicating that an amplification attack ocurred
table amplification_attack_table {
    actions {
        set_amplification_attack_register;
    }
    size : 1;
}

action set_spoofing_attack_register() {
    register_write(spoofing_attack,
                   0,
                   ATTACK);
}

// Table that sets a register indicating that an attack ocurred
table spoofing_attack_table {
    actions {
        set_spoofing_attack_register;
    }
    size : 1;
}

// Increment count register of NTP requests
action set_ntp_monlist_request_count() {
    // Function used to calculate a hash value and store it in hash_val
    modify_field_with_hash_based_offset(custom_ntp_metadata.hash_val, 0, ntp_hash_request, INSTANCE_COUNT);
    // We need to get response bytes in order to calculate the difference between response and request
    register_read(custom_ntp_metadata.response_bytes,
                  ntp_monlist_response_bytes_counter,
                  custom_ntp_metadata.hash_val);
    // Copy value from register ntp_monlist_request_bytes_counter[hash_val]
    // to custom_ntp_metadata.request_bytes
    register_read(custom_ntp_metadata.request_bytes,
                  ntp_monlist_request_bytes_counter,
                  custom_ntp_metadata.hash_val);
    // Increment the value
    add_to_field(custom_ntp_metadata.request_bytes, NTP_REQUEST_DATA_BYTES);
    // Write it back to the register
    register_write(ntp_monlist_request_bytes_counter,
                   custom_ntp_metadata.hash_val,
                   custom_ntp_metadata.request_bytes);
}

table set_ntp_monlist_request_count_table {
    actions {
        set_ntp_monlist_request_count;
    }
    size: 1;
}

// Increment count register of NTP responses
action set_ntp_monlist_response_count() {
    // Function used to calculate a hash value and store it in hash_val
    modify_field_with_hash_based_offset(custom_ntp_metadata.hash_val, 0, ntp_hash_response, INSTANCE_COUNT);
    // We need to get request bytes in order to calculate the difference between response and request
    register_read(custom_ntp_metadata.request_bytes,
                  ntp_monlist_request_bytes_counter,
                  custom_ntp_metadata.hash_val);
    // Copy value from register ntp_monlist_response_bytes_counter[hash_val]
    register_read(custom_ntp_metadata.response_bytes,
                  ntp_monlist_response_bytes_counter,
                  custom_ntp_metadata.hash_val);
    // Increment and write it back to register
    add_to_field(custom_ntp_metadata.response_bytes, ntp_mode7.n_data_items * ntp_mode7.size_data_item);
    register_write(ntp_monlist_response_bytes_counter,
                   custom_ntp_metadata.hash_val,
                   custom_ntp_metadata.response_bytes);
}

table set_ntp_monlist_response_count_table {
    actions {
        set_ntp_monlist_response_count;
    }
    size: 1;
}

// Copy response timestamp to custom ntp metadata
action get_response_TS() {
    // Function used to calculate a hash value and store it in hash_val
    modify_field_with_hash_based_offset(custom_ntp_metadata.hash_val, 0, ntp_hash_response, INSTANCE_COUNT);
    // Get old time stamp
    register_read(custom_ntp_metadata.response_ts,
                  TSResponse,
                  custom_ntp_metadata.hash_val);
}

table get_response_TS_table {
    actions {
        get_response_TS;
    }
    size: 1;
}

// Set response timestamp with the new value
action set_response_TS() {
    // Function used to calculate a hash value and store it in hash_val
    modify_field_with_hash_based_offset(custom_ntp_metadata.hash_val, 0, ntp_hash_response, INSTANCE_COUNT);
    // Update time stamp
    register_write(TSResponse,
                   custom_ntp_metadata.hash_val,
                   intrinsic_metadata.ingress_global_timestamp);
}

table set_response_TS_table {
    actions {
        set_response_TS;
    }
    size: 1;
}

control ingress {
    apply(egress_port);
    // NTP_GET_MONLIST operations and is a valid UDP header.
    if( ntp_mode7.req_code == NTP_GETMONLIST_CODE and valid(udp) ) {
        if ( ntp_first.r == NTP_REQUEST ) {
            apply(set_ntp_monlist_request_count_table);
            if ( custom_ntp_metadata.egress_port != standard_metadata.ingress_port ) {
                //Spoofing
                apply(spoofing_attack_table);
            }
        }
        if ( ntp_first.r == NTP_RESPONSE ) {
            apply(set_ntp_monlist_response_count_table);
            apply(get_response_TS_table);
            apply(set_response_TS_table);
            // If new_timestamp - old_timestamp is lower than threshold: check for bytes 
            if ( intrinsic_metadata.ingress_global_timestamp - custom_ntp_metadata.response_ts < TS_THRESHOLD ) {
                // Check for Amplification attack
                if ( (custom_ntp_metadata.response_bytes - custom_ntp_metadata.request_bytes) > BYTES_THRESHOLD ) {
                    apply(amplification_attack_table);
                }
            } else {
                // Two responses for same index came far apart from each other. This may not be an attack.
            }
        }
        apply(set_ntp_count_table);
    }
    apply(ipv4_lpm);
    apply(forward);
}

control egress {
}
