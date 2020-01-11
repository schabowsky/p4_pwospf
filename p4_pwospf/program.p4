/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8> TYPE_OSPF = 0x59;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<9>  ingressSpec_t;
typedef bit<16> mcast_grp_t;
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

header ospfv2_t {
    bit<8>    version;
    bit<8>    msgType;
    bit<16>   msgLen;
    bit<32>   routerId;
    bit<32>   areaId;
    bit<16>   hdrChecksum;
    bit<16>   authType;
    bit<64>   auth;
}

header cpu_metadata_t {
    macAddr_t   ingressPort;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    ospfv2_t        ospfv2;
    cpu_metadata_t  cpu_metadata;
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
        transition select (hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select (hdr.ipv4.protocol) {
            TYPE_OSPF : parse_ospf;
            default : accept;
        }
    }

    state parse_ospf {
        packet.extract(hdr.ospfv2);
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

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ospf_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mcg(mcast_grp_t mcast_group) {
        standard_metadata.mcast_grp = mcast_group;
    }

    action set_cpu_meta(macAddr_t inPort) {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.ingressPort = inPort;
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

    table ospf_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ospf_forward;
            drop;
        }
        size = 1024;
    }

    table mcg_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            set_mcg;
    	    drop;
        }
        size = 1024;
    }

    table inport_table {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_cpu_meta;
    	    drop;
        }
        size = 1024;
    }

    apply {
        if (hdr.ipv4.isValid() && !hdr.ospfv2.isValid()) {
            ipv4_lpm.apply();
        }
        if (hdr.ospfv2.isValid()) {
            if (standard_metadata.ingress_port == 4) {
                // Packet to send (received from controller).
                mcg_table.apply();
                ospf_table.apply();
            } else {
                // Packet from other switch (pass to controller).
                inport_table.apply();
                if (hdr.cpu_metadata.isValid()) {
                    ospf_forward(4);
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        // Prune multicast packet to ingress port to preventing loop
        if (standard_metadata.egress_port == standard_metadata.ingress_port)
            drop();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ospfv2);
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
