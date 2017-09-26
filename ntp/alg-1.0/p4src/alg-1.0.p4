/*
 * author: Roberto Cordoni
 * email: rocordoni@gmail.com
 *
 * P4 Control program for algorithm 1.0.
 */

#include "includes/headers.p4"
#include "includes/parser.p4"

#define INSTANCE_COUNT 32
#define MONLIST_ATTACK_THRESHOLD 0
#define NTP_GETMONLIST_CODE 0x2a
#define NTP_REQUEST 0
#define NTP_RESPONSE 1
#define ATTACK 1
#define REGISTER_WIDTH 16

header_type custom_ntp_metadata_t {
    fields {
        hash_val: INSTANCE_COUNT;
        count_val1: 30;
        egress_port: 2;
    }
}

header_type custom_metadata_t {
    fields {
        nhop_ipv4: 32;
    }
}

// Instantiate custom metadata
metadata custom_metadata_t custom_metadata;
metadata custom_ntp_metadata_t custom_ntp_metadata;

register attack{
    width : REGISTER_WIDTH;
    instance_count : 1;
}

register ntp_counter{
    width : REGISTER_WIDTH;
    instance_count : 1;
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

action set_attack_register() {
    register_write(attack,
                   0,
                   ATTACK);
}

// Table that sets a register indicating that an attack ocurred
table attack_table {
    actions {
        set_attack_register;
    }
    size : 1;
}

control ingress {
    apply(egress_port);
    // NTP_GET_MONLIST operations and is a valid UDP header.
    if( ntp_mode7.req_code == NTP_GETMONLIST_CODE and valid(udp) ) {
        if ( ntp_first.r == NTP_REQUEST ) {
            if ( custom_ntp_metadata.egress_port != standard_metadata.ingress_port ) {
                //Spoofing
                apply(attack_table);
            }
        }
        apply(set_ntp_count_table);
    }
    apply(ipv4_lpm);
    apply(forward);
}

control egress {
}
