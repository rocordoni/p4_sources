/*
 * author: Roberto Cordoni
 * email: rocordoni@gmail.com
 *
 * Headers definition.
 */

header_type ethernet_t {
    fields {
        dstAddr     : 48;
        srcAddr     : 48;
        etherType   : 16;
    }
}

header_type ipv4_t {
    fields {
        version         : 4;
        ihl             : 4;
        diffserv        : 8;
        totalLen        : 16;
        identification  : 16;
        flags           : 3;
        fragOffset      : 13;
        ttl             : 8;
        protocol        : 8;
        hdrChecksum     : 16;
        srcAddr         : 32;
        dstAddr         : 32;
    }
}

header_type tcp_t {
    fields {
        srcPort     : 16;
        dstPort     : 16;
        seqNo       : 32;
        ackNo       : 32;
        dataOffset  : 4;
        res         : 3;
        ecn         : 3;
        ctrl        : 6;
        window      : 16;
        checksum    : 16;
        urgentPtr   : 16;
    }
}

header_type udp_t {
    fields {
        srcPort     : 16;
        dstPort     : 16;
        length_     : 16;
        checksum    : 16;
    }
}

header_type ntp_first_t {
    fields {
        r       : 1;
        m       : 1;
        version : 3;
        mode    : 3;
    }
}

header_type ntp_mode7_t {
    fields {
        a               : 1;
        sequence        : 7;
        implementation  : 8;
        req_code        : 8;
        err             : 4;
        n_data_items    : 12;
        mbz             : 4;
        size_data_item  : 12;
    }
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

