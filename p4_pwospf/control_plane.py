#!/usr/bin/env python
import sys
import os
import time
import binascii
from threading import Thread
from datetime import timedelta

from scapy.all import sniff, sendp, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP, Packet, raw
from timeloop import Timeloop
from scapy_ospf import PWOSPF_LSA, PWOSPF_LSU, PWOSPF_Hello, OSPF_Hdr, CPU_metadata
import psycopg2
import grpc
from netaddr import IPAddress, IPNetwork

import controller_utils as cu
import queries
# TODO: Make it in a prettier way.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '../utils/'))
import p4runtime_lib.bmv2


class Controller:
    """Main script class."""
    HELLO_INT = 10
    LSU_INT = 30
    LSU_SEQ = 1
    DB_REFRESH_INT = 1

    def __init__(self, device_id):
        """Init method."""

        self.CTRL_IFACE, self.RID = cu.get_ctrl_if_and_rid(device_id)
        self.p4info_helper = cu.get_p4info_helper()
        self.switch_conn = cu.create_switch_connection(self.p4info_helper, device_id)
        db = cu.get_db_name(device_id)
        self.con = psycopg2.connect(database=db, user="atsi", password="atsi", host="127.0.0.1", port="5432")
        self.cur = self.con.cursor()
        self.tl = Timeloop()

        @self.tl.job(interval=timedelta(seconds=self.HELLO_INT))
        def send_hello():
            """Send Hello message periodically (every HELLO_INT)."""
            ether_pkt = Ether(
                src=get_if_hwaddr(self.CTRL_IFACE), dst='ff:ff:ff:ff:ff:ff')
            ip_hdr = IP(src=self.RID, dst=cu.ALLSPFRouters)
            ospf_hdr = OSPF_Hdr(type=1, src=self.RID)
            hello_hdr = PWOSPF_Hello(
                mask="255.255.255.248",
                hellointerval=self.HELLO_INT
            )
            pkt = ether_pkt / ip_hdr / ospf_hdr / hello_hdr
            # pkt.show2()
            sendp(pkt, iface=self.CTRL_IFACE, verbose=False)
            print("Hello sent.")

        @self.tl.job(interval=timedelta(seconds=self.LSU_INT))
        def send_lsu():
            """Send LSU message periodically (every LSU_INT)."""

            self.cur.execute(queries.SELECT_NEIGHBORS)
            routers = self.cur.fetchall()

            ether_pkt = Ether(
                src=get_if_hwaddr(self.CTRL_IFACE), dst='ff:ff:ff:ff:ff:ff')
            ospf_hdr = OSPF_Hdr(type=4, src=self.RID)

            self.cur.execute(queries.SELECT_LINKS)
            links = self.cur.fetchall()
            lsa_list = None
            for l in links:
                ip = IPNetwork(l[1])
                subnet, mask = ip.ip, ip.netmask
                rid = l[2]
                lsa = PWOSPF_LSA(subnet=subnet, mask=mask, rid=rid)
                lsa_list = lsa if not lsa_list else [lsa_list| lsa]

            lsu_hdr = PWOSPF_LSU(seq=self.LSU_SEQ, ttl=1, lsalist=[lsa_list])

            pkts = []
            for r in routers:
                ip_pkt = ether_pkt / IP(src=self.RID, dst=r[1])
                pkt = ip_pkt / ospf_hdr / lsu_hdr / lsa_list
                pkts.append(pkt)
            for p in pkts:
                p.show2()
                sendp(p, iface=self.CTRL_IFACE, verbose=False)
            print("LSU sent.")
            # TODO: Increment if data has changed.
            # self.seq = self.seq + 1

        @self.tl.job(interval=timedelta(seconds=self.DB_REFRESH_INT))
        def check_db():
            """Check if none of records in database expired."""

            self.cur.execute(queries.SELECT_NEIGHBORS)
            routers = self.cur.fetchall()
            to_delete = []
            for router in routers:
                if router[4] + (3 * router[3]) < time.time():
                    to_delete.append(router[0])
            if to_delete:
                to_delete = tuple(to_delete)
                # TODO: Remove links, then neighbor.
                self.cur.execute(queries.REMOVE_NEIGHBOR, (to_delete,))
                self.con.commit()
                print("Deleted!")
                # TODO: Calculate Shortest Path!


    def read_table_rules(self):
        """Read table rules from switch."""
        print "Read table rules..."
        for response in self.switch_conn.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table_name = self.p4info_helper.get_tables_name(entry.table_id)
                print entity
                for m in entry.match:
                    print self.p4info_helper.get_match_field_name(table_name, m.field_id)
                    print self.p4info_helper.get_match_field_value(m)
                action = entry.action.action
                action_name = self.p4info_helper.get_actions_name(action.action_id)
                print '->', action_name
                for p in action.params:
                    print self.p4info_helper.get_action_param_name(action_name, p.param_id)
                    print p.value


    def handle_hello_msg(self, pkt, ingress_port):
        rid = pkt[OSPF_Hdr].src
        hello_int = pkt[PWOSPF_Hello].hellointerval
        last_hello = time.time()
        self.cur.execute(queries.SELECT_NEIGHBOR, (rid,))
        router = self.cur.fetchone()
        if router:
            self.cur.execute(
                queries.UPDATE_NEIGHBOR, (last_hello, router[1],))
        else:
            self.cur.execute(
                queries.INSERT_NEIGHBOR,
                (rid, ingress_port, hello_int, last_hello,))
            self.write_ospf_table(rid, ingress_port)
            # TODO: Save link to database.
            mask = IPAddress(pkt[PWOSPF_Hello].mask).netmask_bits()
            subnetwork = pkt[IP].src.split('.')
            subnetwork = '.'.join(subnetwork[:-1]) + '.10/' + str(mask)
            self.cur.execute(queries.INSERT_LINK, (subnetwork, rid, hex(0)))
            print 'Link created!'
        self.con.commit()


    def write_ospf_table(self, rid, ingress_port):
        try:
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ospf_table",
                match_fields={
                    "hdr.ipv4.dstAddr": rid
                },
                action_name="MyIngress.ospf_forward",
                action_params={
                    "port": cu.match_hdw_port(ingress_port)
                })
            self.switch_conn.WriteTableEntry(table_entry)
        except grpc.RpcError as e:
            print "GRPC error: {}".format(e)


    def handle_pkt(self, pkt):
        binary_data = raw(pkt)
        string_data = binascii.hexlify(binary_data)
        cpu_meta = CPU_metadata(binascii.unhexlify(string_data[:12]))
        pkt = Ether(binascii.unhexlify(string_data[12:]))

        if OSPF_Hdr in pkt and self.RID == pkt[OSPF_Hdr].src:
            return

        if PWOSPF_Hello in pkt:
            ingress_port = cpu_meta.inport
            rid = pkt[OSPF_Hdr].src
            print "Got a hello packet from {} on port {}".format(rid, ingress_port)
            # pkt.show2()
            self.handle_hello_msg(pkt, ingress_port)
        elif PWOSPF_LSU in pkt:
            pkt.show2()
            # TODO: Handle OSPF LSU packets.
            pass


    def run(self):
        self.tl.start()
        print "Control plane started on interface {} | RID: {}".format(self.CTRL_IFACE, self.RID)

        try:
            print "Sniffing on {}".format(self.CTRL_IFACE)
            sys.stdout.flush()
            sniff(iface=self.CTRL_IFACE, prn=lambda x: self.handle_pkt(x))
        except KeyboardInterrupt:
            self.tl.stop()
            self.switch_conn.shutdown()
            self.con.close()


def main():
    if len(sys.argv) < 2:
        print 'Missing argument: <device_id>'
        exit(1)
    controller = Controller(sys.argv[1])
    controller.run()


if __name__ == '__main__':
    main()
