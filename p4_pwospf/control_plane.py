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
from dijkstra import get_shortest_path
# TODO: Make it in a prettier way.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '../utils/'))
import p4runtime_lib.bmv2


class Controller:
    """Main script class."""
    HELLO_INT = 10
    LSU_INT = 30
    LSU_TIMEOUT = 40
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
            self.cur.execute(queries.SELECT_ALL_NEIGHBORS)
            routers = self.cur.fetchall()

            ether_pkt = Ether(
                src=get_if_hwaddr(self.CTRL_IFACE), dst='ff:ff:ff:ff:ff:ff')
            ospf_hdr = OSPF_Hdr(type=4, src=self.RID)

            self.cur.execute(queries.SELECT_ALL_LINKS)
            links = self.cur.fetchall()
            lsa_list = []

            for l in links:
                ip = IPNetwork(l[1])
                subnet, mask = ip.ip, ip.netmask
                rid = l[3]
                lsa = PWOSPF_LSA(subnet=subnet, mask=mask, rid=rid)
                lsa_list.append(lsa)

            if lsa_list:
                lsu_hdr = PWOSPF_LSU(seq=self.LSU_SEQ, ttl=1, lsalist=lsa_list)
                pkts = []
                for r in routers:
                    ip_pkt = ether_pkt / IP(src=self.RID, dst=r[1])
                    pkt = ip_pkt / ospf_hdr / lsu_hdr
                    pkts.append(pkt)
                for p in pkts:
                    p.show2()
                    sendp(p, iface=self.CTRL_IFACE, verbose=False)
                print("LSU sent.")
                self.LSU_SEQ = self.LSU_SEQ + 1

        @self.tl.job(interval=timedelta(seconds=self.DB_REFRESH_INT))
        def check_db():
            """Check if none of records in database expired."""
            self.cur.execute(queries.SELECT_ALL_NEIGHBORS)
            routers = self.cur.fetchall()
            self.remove_inactive_neighbors(routers)
            self.cur.execute(queries.SELECT_ALL_LINKS)
            links = self.cur.fetchall()
            self.remove_inactive_links(links)

    def remove_inactive_neighbors(self, routers):
        to_delete = []
        for router in routers:
            if router[4] + (3 * router[3]) < time.time():
                to_delete.append(router[0])
                self.cur.execute(queries.REMOVE_LINK, (router[1],))
        if to_delete:
            to_delete = tuple(to_delete)
            self.cur.execute(queries.REMOVE_NEIGHBORS, (to_delete,))
            self.con.commit()
            # Trigger Dijkstra.
            self.get_paths()

    def remove_inactive_links(self, links):
        to_delete = []
        for link in links:
            if link[2] + self.LSU_TIMEOUT < time.time():
                to_delete.append(link[0])
        if to_delete:
            to_delete = tuple(to_delete)
            self.cur.execute(queries.REMOVE_LINKS, (to_delete,))
            self.con.commit()
            # Trigger Dijkstra.
            self.get_paths()

    def get_paths(self):
        self.cur.execute(queries.SELECT_ALL_LINKS)
        links = self.cur.fetchall()
        if links:
            # return get_shortest_path(self.RID, links)
            pass
        return []

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
        # Select all neighbors from controller's database.
        self.cur.execute(queries.SELECT_NEIGHBOR, (rid,))
        router = self.cur.fetchone()
        if router:
            # Update neighbor's timestamp.
            self.cur.execute(
                queries.UPDATE_NEIGHBOR_TS, (last_hello, rid,))
        else:
            # Create new record in database.
            self.cur.execute(
                queries.INSERT_NEIGHBOR,
                (rid, ingress_port, hello_int, last_hello,))
            # Create forward rule in switch (for LSU messages).
            self.write_ospf_table(rid, ingress_port)
            # Save link to database.
            mask = IPAddress(pkt[PWOSPF_Hello].mask).netmask_bits()
            subnetwork = pkt[IP].src.split('.')
            subnetwork = '.'.join(subnetwork[:-1]) + '.10/' + str(mask)
            self.cur.execute(queries.INSERT_LINK, (subnetwork, last_hello, rid))
        self.con.commit()

    def save_links_to_db(self, lsa_list):
        for lsa in lsa_list:
            # lsa.show2()
            rid = lsa.rid
            subnet = lsa.subnet
            mask = IPAddress(lsa.mask).netmask_bits()
            subnet = subnet + '/' + str(mask)
            self.cur.execute(queries.SELECT_LINK, (subnet, rid,))
            link = self.cur.fetchone()
            ts = time.time()
            if link:
                self.cur.execute(queries.UPDATE_LINK, (ts, subnet, rid,))
            else:
                self.cur.execute(queries.INSERT_LINK, (subnet, ts, rid,))

    def handle_lsu_msg(self, pkt):
        rid = pkt[OSPF_Hdr].src
        seq_number = pkt[PWOSPF_LSU].seq
        self.cur.execute(queries.SELECT_NEIGHBOR, (rid,))
        router = self.cur.fetchone()
        if router:
            last_seq_number = router[5]
            lsa_list = pkt[PWOSPF_LSU].lsalist
            if not last_seq_number:
                print "First LSU from this neighbor."
                # First LSU from this neighbor.
                self.cur.execute(queries.UPDATE_NEIGHBOR_SEQ, (hex(seq_number), rid))
                self.save_links_to_db(lsa_list)
            elif last_seq_number != seq_number:
                print "Link set of neighbor has changed."
                # Link set of neighbor has changed.
                self.cur.execute(queries.UPDATE_NEIGHBOR_SEQ, (hex(seq_number), rid))
                self.save_links_to_db(lsa_list)
            else:
                # Nothing changed. Drop packet.
                return
            self.con.commit()
        else:
            # Neighbor was inactive so it's no longer in database.
            return

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

    def write_ipv4_table(self, ip, egress_port):
        try:
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={
                    "hdr.ipv4.dstAddr": ip
                },
                action_name="MyIngress.ipv4_forward",
                action_params={
                    "dstAddr": 'ff:ff:ff:ff:ff:ff',
                    "port": egress_port
                })
            self.switch_conn.WriteTableEntry(table_entry)
        except grpc.RpcError as e:
            print "GRPC error: {}".format(e)

    def handle_pkt(self, pkt):
        binary_data = raw(pkt)
        string_data = binascii.hexlify(binary_data)
        cpu_meta = CPU_metadata(binascii.unhexlify(string_data[:12]))
        pkt = Ether(binascii.unhexlify(string_data[12:]))

        if OSPF_Hdr in pkt:
            if self.RID == pkt[OSPF_Hdr].src:
                # Packet sent from this controller.
                return

            ingress_port = cpu_meta.inport
            rid = pkt[OSPF_Hdr].src

            if PWOSPF_Hello in pkt:
                print "Got a hello packet from {} on port {}".format(rid, ingress_port)
                # pkt.show2()
                self.handle_hello_msg(pkt, ingress_port)
            elif PWOSPF_LSU in pkt:
                print "Got a LSU packet from {} on port {}".format(rid, ingress_port)
                # pkt.show2()
                self.handle_lsu_msg(pkt)

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
