/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "includes/headers.p4"
#include "includes/parser.p4"

// TODO: Define the threshold value
#define MONLIST_ATTACK_THRESHOLD 0
#define NTP_GETMONLIST_CODE 0x2a
#define NTP_REQUEST 0
#define NTP_RESPONSE 1

field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}

header_type custom_metadata_t {
    fields {
        nhop_ipv4: 32;
        // TODO: Add the metadata for hash indices and count values
        hash_val1: 16;
        hash_val2: 16;
        count_val1: 16;
        count_val2: 16;
    }
}

header_type custom_ntp_metadata_t {
    fields {
        dropped_packets_count: 16;
        hash_val1: 16;
        count_val1: 16;
        request_count : 16;
        response_count: 16;
    }
}

metadata custom_metadata_t custom_metadata;
metadata custom_ntp_metadata_t custom_ntp_metadata;

action set_nhop(nhop_ipv4, port) {
    modify_field(custom_metadata.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    add_to_field(ipv4.ttl, -1);
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

// TODO: Define the field list to compute the hash on
// Use the 5 tuple of 
// (src ip, dst ip, src port, dst port, ip protocol)

field_list hash_fields_ntp {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
    udp.srcPort;
    udp.dstPort;
}

// TODO: Define two different hash functions to store the counts
// Please use csum16 and crc16 for the hash functions

field_list_calculation ntp_hash {
    input { 
        hash_fields_ntp;
    }
    algorithm : crc16;
    output_width : 16;
}

register dropped_flows_counter{
    width : 16;
    instance_count : 1;
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

action _drop_ntp() {
    register_read(custom_ntp_metadata.dropped_packets_count, dropped_packets_counter,
                  0);
    add_to_field(custom_ntp_metadata.dropped_packets_count, 1);
    register_write(dropped_packets_counter, 0, custom_ntp_metadata.dropped_packets_count);
    drop();
}

action set_ntp_count() {
    // Increment count register of ntp packets
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

action set_ntp_monlist_request_count() {
    // Increment count register of NTP requests
    modify_field_with_hash_based_offset(custom_ntp_metadata.hash_val1, 0,
                                        ntp_hash, 16);
    register_read(custom_ntp_metadata.count_val1, ntp_monlist_request_counter, 
                  custom_ntp_metadata.hash_val1);
    add_to_field(custom_ntp_metadata.count_val1, 1);
    register_write(ntp_monlist_request_counter, custom_ntp_metadata.hash_val1, 
                   custom_ntp_metadata.count_val1);
}

table set_ntp_monlist_request_count_table {
    actions {
        set_ntp_monlist_request_count;
    }
    size: 1;
}

action set_ntp_monlist_response_count() {
    // Increment count register of NTP responses
    modify_field_with_hash_based_offset(custom_ntp_metadata.hash_val1, 0,
                                        ntp_hash, 16);
    register_read(custom_ntp_metadata.count_val1, ntp_monlist_response_counter,
                  custom_ntp_metadata.hash_val1);
    add_to_field(custom_ntp_metadata.count_val1, 1);
    register_write(ntp_monlist_response_counter, custom_ntp_metadata.hash_val1,
                   custom_ntp_metadata.count_val1);
}

table set_ntp_monlist_response_count_table {
    actions {
        set_ntp_monlist_response_count;
    }
    size: 1;
}

action get_req_resp_count() {
    // Get request and response counters into req_resp_metadata
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

// TODO: Define table to drop the ntp traffic
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
    if(ntp_mode7.req_code == NTP_GETMONLIST_CODE and valid(udp)) {
        if ( ntp_first.r == NTP_REQUEST ) {
            apply(set_ntp_monlist_request_count_table);
        } else {
            apply(set_ntp_monlist_response_count_table);
            apply(get_req_resp_count_table);
            if ( custom_ntp_metadata.response_count - custom_ntp_metadata.request_count > MONLIST_ATTACK_THRESHOLD ) {
                // drop package
                apply(drop_ntp_table);
            } else {
                
            }
        }
        apply(set_ntp_count_table);
    }
}

control egress {
    apply(send_frame);
}
