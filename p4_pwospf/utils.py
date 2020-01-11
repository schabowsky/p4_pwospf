import sys

from scapy.all import get_if_list, get_if_raw_addr, get_alias_address
# TODO: Make it in a prettier way.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import p4runtime_lib

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


def create_switch_connection(device_id):
    conn = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=device_id.replace('c', 's'),
            address='127.0.0.1:{}'.format(GRPC_PORTs[device_id]),
            # device_id=0,
            proto_dump_file='logs/{}-p4runtime-requests.txt'.format(device_id))
    conn.MasterArbitrationUpdate()
    return conn
