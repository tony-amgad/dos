import socket
import struct
import textwrap
import os
import time

dict_ips={}
max_interval=60
threshold_num=10
threshold_time=0.05
dropped_array = []

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

local_ip = get_ip_address()
#print(local_ip)


def block_ip(ip_block):
    os.system('sudo iptables -A INPUT -s {} -j DROP'.format(ip_block))

def DetectLegitimateIp(ip_input,req_time,req_type):
    global dropped_array, local_ip
    if ip_input in dict_ips:
#        print(dict_ips)
        dict_ips[ip_input]['count']+=1
        #check interval time
        if dict_ips[ip_input]['count'] >=threshold_num:
            #print(float(req_time-dict_ips[ip_input]['Ftime']))
            if req_time-dict_ips[ip_input]['Ftime'] <threshold_time:
                if ip_input != local_ip:
                    print('=====dos attack with ip : {}'.format(ip_input))
                #prevent function
                if ip_input != local_ip and not (ip_input in dropped_array):
                    block_ip(ip_input)
                    dropped_array.append(ip_input)
                    print('{} is blocked'.format(ip_input))
            else:
                dict_ips[ip_input]['Ftime']=req_time
                dict_ips[ip_input]['count']=1

    else:
        dict_ips[ip_input]={'Ftime':req_time,'count':1}






def main():
    conn=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    while True:
        raw_data,addr=conn.recvfrom(65536)
        dest_mac,src_mac,eth_proto,data=ethernet_frame(raw_data)
#        print('\n Ethernet frame:')
#        print('Destination: {}, Source: {},Protocol: {}'.format(dest_mac,src_mac,eth_proto))
        #ipv4 
        if eth_proto==8:
            (version,header_length,ttl,proto,src,target,data)=ipv4_packet(data)
#            print(' IPV4 packet:')
#            print('     version: {},Header Length: {},Ttl: {}'.format(version,header_length,ttl))
#            print('     Protocol: {},Source: {},Target: {}'.format(proto,src,target))
            if proto==1:
                icmp_type,code,checksum,data=icmp_packet(data)
                DetectLegitimateIp(src,time.time(),proto)
#                print(' ICMP packet:')
#                print('     Type: {},Code: {},Checksum:{}'.format(icmp_type,code,checksum))
#                print('     Data: ')
#                print(format_multi_line('           ',data))
            elif proto==6:
                pass
#                print(' TCP segment:')
                src_port,dest_port,sequence,acknoledgment,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data=tcp_segment(data)
            elif proto==17:
                pass
#                print(' UDP segment: ')
                #src_port,dest_port,size,data=udp_segment(data)
            else:
                pass
#                print('     Data: ')
#                print(format_multi_line('           ',data))






#unpack ethernet frame
def ethernet_frame(data):
    dest_mac,src_mac,proto=struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(dest_mac),get_mac_addr(src_mac),socket.htons(proto),data[14:]

#formated mac address AA:00:CC:...........
def get_mac_addr(bytes_addr):
    bytes_str=map('{:02x}'.format,bytes_addr)
    return ':'.join(bytes_str).upper()
#ipv4 dotted notation 127.0.0.1
def ipv4(addr):
    return '.'.join(map(str,addr))

#unpacking IPV4 packet
def ipv4_packet(data):
    version_header_length=data[0]
    version=version_header_length>>4
    header_length=(version_header_length&15)*4
    ttl,proto,src,target=struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version,header_length,ttl,proto,ipv4(src),ipv4(target),data[header_length:]



def icmp_packet(data):
    icmp_type,code,checksum=struct.unpack('! B B H',data[:4])
    return icmp_type,code,checksum,data[4:]


def tcp_segment(data):
    (src_port,dest_port,sequence,acknoledgment,offset_reserved_flags)=struct.unpack('! H H L L H',data[:14])
    offset=(offset_reserved_flags>>12)*4
    flag_urg=(offset_reserved_flags&32)>>5
    flag_ack=(offset_reserved_flags&16)>>4
    flag_psh=(offset_reserved_flags&8)>>3
    flag_rst=(offset_reserved_flags&4)>>2
    flag_syn=(offset_reserved_flags&2)>>1
    flag_fin=offset_reserved_flags&1
    return src_port,dest_port,sequence,acknoledgment,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data[offset:]


def udp_segment(data):
    src_port,dest_port,size=struct.unpack('! H H 2X H',data[:8])
    return  src_port,dest_port,size,data[8:]

def format_multi_line(prefix,string,size=80):
    size-=len(prefix)
    if isinstance(string,bytes):
        string=''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size%2:
            size-=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])


main()
