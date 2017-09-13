/*
 * author: Roberto Cordoni
 * email: rocordoni@gmail.com
 *
 * P4 Control program -- NTP Packet Asymmetry.
 */

#include "includes/headers.p4"
#include "includes/parser.p4"

#define MONLIST_ATTACK_THRESHOLD 0
#define NTP_GETMONLIST_CODE 0x2a
#define NTP_REQUEST 0
#define NTP_RESPONSE 1

header_type custom_ntp_metadata_t {
    fields {
        dropped_packets_count: 16;
        hash_val1: 16;
        count_val1: 16;
        request_count : 16;
        response_count: 16;
    }
}

// Instantiate custom ntp metadata
metadata custom_ntp_metadata_t custom_ntp_metadata;

// Use the 5 tuple of (src ip, dst ip, src port, dst port, ip protocol)
field_list hash_fields_ntp {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    udp.srcPort;
    udp.dstPort;
}

// Using crc16 for the hash functions
field_list_calculation ntp_hash {
    input {
        hash_fields_ntp;
    }
    algorithm : crc16;
    output_width : 16;
}

register ntp_counter{
    width : 16;
    instance_count : 1;
}

register ntp_monlist_request_counter{
    width : 16;
    instance_count : 16;
}

register ntp_monlist_response_counter{
    width : 16;
    instance_count : 16;
}

register dropped_packets_counter{
    width : 16;
    instance_count : 1;
}

action _drop() {
    drop();
}

// ******************** NTP ACTION ***********************


// Increment dropped packets counter and drop packet.
action _drop_ntp() {
    register_read(custom_ntp_metadata.dropped_packets_count, dropped_packets_counter,
                  0);
    add_to_field(custom_ntp_metadata.dropped_packets_count, 1);
    register_write(dropped_packets_counter, 0, custom_ntp_metadata.dropped_packets_count);
    drop();
}

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

// Increment count register of NTP requests
action set_ntp_monlist_request_count() {
    // Function used to calculate a hash value and store it in hash_val1
    modify_field_with_hash_based_offset(custom_ntp_metadata.hash_val1, 0, ntp_hash, 16);
    // Copy value from register ntp_monlist_request_counter[hash_val1]
    // to custom_ntp_metadata.count_val1
    register_read(custom_ntp_metadata.count_val1,
                  ntp_monlist_request_counter,
                  custom_ntp_metadata.hash_val1);
    // Increment the value
    add_to_field(custom_ntp_metadata.count_val1, 1);
    // Write it back to the register
    register_write(ntp_monlist_request_counter,
                   custom_ntp_metadata.hash_val1,
                   custom_ntp_metadata.count_val1);
}

table set_ntp_monlist_request_count_table {
    actions {
        set_ntp_monlist_request_count;
    }
    size: 1;
}

// Increment count register of NTP responses
action set_ntp_monlist_response_count() {
    // Function used to calculate a hash value and store it in hash_val1
    modify_field_with_hash_based_offset(custom_ntp_metadata.hash_val1, 0, ntp_hash, 16);
    // Copy value from register ntp_monlist_response_counter[hash_val1]
    register_read(custom_ntp_metadata.count_val1,
                  ntp_monlist_response_counter,
                  custom_ntp_metadata.hash_val1);
    // Increment and write it back to register
    add_to_field(custom_ntp_metadata.count_val1, 1);
    register_write(ntp_monlist_response_counter,
                   custom_ntp_metadata.hash_val1,
                   custom_ntp_metadata.count_val1);
}

table set_ntp_monlist_response_count_table {
    actions {
        set_ntp_monlist_response_count;
    }
    size: 1;
}

// Get request and response counters into req_resp_metadata
action get_req_resp_count() {
    register_read(custom_ntp_metadata.request_count, ntp_monlist_request_counter,
                  custom_ntp_metadata.hash_val1);
    register_read(custom_ntp_metadata.response_count, ntp_monlist_response_counter,
                  custom_ntp_metadata.hash_val1);
    // Increment response count metadata, NOT THE COUNT REGISTER
    add_to_field(custom_ntp_metadata.response_count, 1);

}

table get_req_resp_count_table {
    actions {
        get_req_resp_count;
    }
    size: 1;
}

table drop_ntp_table {
    actions { _drop_ntp; }
    size: 1;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

control ingress {
    // NTP_GET_MONLIST operations and is a valid UDP header.
    if(ntp_mode7.req_code == NTP_GETMONLIST_CODE and valid(udp)) {
        if ( ntp_first.r == NTP_REQUEST ) {
            // For a request, increment request counter
            apply(set_ntp_monlist_request_count_table);
        } else {
            // For a response: increment response counter,
            // copy the request/response counter to custom_ntp_metadata
            // and check if the difference between them is above threshold
            apply(set_ntp_monlist_response_count_table);
            apply(get_req_resp_count_table);
            if ( custom_ntp_metadata.response_count - custom_ntp_metadata.request_count > MONLIST_ATTACK_THRESHOLD ) {
                // drop package
                apply(drop_ntp_table);
            }
        }
        // NTP MONLIST Packet counter
        apply(set_ntp_count_table);
    }
}

control egress {
    apply(send_frame);
}
