import sys

from scapy.all import get_if_list, get_if_raw_addr, get_alias_address
# TODO: Make it in a prettier way.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
from p4runtime_lib.bmv2 import Bmv2SwitchConnection
from p4runtime_lib.helper import P4InfoHelper
import grpc

ALLSPFRouters = "224.0.0.5"
IPs = {
    'c1': '10.0.11.1',
    'c2': '10.0.12.1',
    'c3': '10.0.13.1',
    'c4': '10.0.14.1',
    'c5': '10.0.15.1'
}
DBs = {
    'c1': 'atsi1',
    'c2': 'atsi2',
    'c3': 'atsi3',
    'c4': 'atsi4',
    'c5': 'atsi5'
}
GRPC_PORTs = {
    'c1': 50051,
    'c2': 50052,
    'c3': 50053,
    'c4': 50054,
    'c5': 50055
}


def get_if(device_id):
    iface = None
    port = device_id + '-eth0'
    for i in get_if_list():
        if port in i:
            return i
    print "Cannot find control plane interface!"
    exit(1)


def get_ip(device_id):
    if device_id in IPs.keys():
        return IPs[device_id]
    print "Cannot find router IP!"
    exit(1)


def get_ctrl_if_and_rid(id):
    return get_if(id), get_ip(id)


def get_db_name(device_id):
    if device_id in DBs.keys():
        return DBs[device_id]
    print "Cannot find database!"
    exit(1)


def get_p4info_helper():
    return P4InfoHelper("build/program.p4.p4info.txt")


def create_switch_connection(p4info_helper, device_id):
    switch_name = device_id.replace('c', 's')
    dev_id = int(device_id[-1:]) - 1
    conn = Bmv2SwitchConnection(
            name=switch_name,
            address='127.0.0.1:{}'.format(GRPC_PORTs[device_id]),
            device_id=dev_id,
            proto_dump_file='logs/{}-p4runtime-requests.txt'.format(switch_name))
    try:
        conn.MasterArbitrationUpdate()
        bmv2_file = "topo/{}-runtime.json".format(switch_name)
        conn.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file)
    except grpc.RpcError as e:
        # Forwarding pipeline have been already configured.
        print "GRPC error: {}".format(e)
        # conn.shutdown()
    return conn


def match_hdw_port(port):
    return int(port[-1:])
