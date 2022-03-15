"""pcap2csv
Script to extract specific pieces of information from a pcap file and
render into a csv file.
Usage: <program name> --pcap <input pcap file> --csv <output pcap file>
Each packet in the pcap is rendered into one row of the csv file.
The specific items to extract, and the order in which they are rendered
in the csv are hard-coded in the script, in the 'render_csv_row' function.
Also note that the separators in the csv are '|' characters, not commas.
This script uses *both* PyShark (https://kiminewt.github.io/pyshark/) and
Scapy to do its work. PyShark because we want to leverage tshark's powerful
protocol decoding ability to generate the "textual description" field of
the CSV, and Scapy because at the same time we want to access the "payload"
portion of the packet (PyShark seems to be unable to provide this).
"""
#=================ĐỌC DÒNG COMMENT ĐẦU TIÊN LÀ ĐỦ========
import argparse
import os.path
import sys
import os
import time
#import subprocess
import pyshark
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
import re
import csv

dem = 0
daylaTLSv1handshake = False
# import socket
# hostname = socket.gethostname()
# iplocal = socket.gethostbyname(hostname)

ipMayTanCong = ""

outfile_ipmaytancong = open('D:\lequangnhu\ipmaytancong.txt','w')


#outfile_GomCum = open('D:/blukeep_gomcum.csv','w')
outfile = open('D:/dataset_ftp.csv','w')

#====PHẢI THAY ĐỔI ĐƯỜNG DẪN 3 FILE DƯỚI NÀY. LÀ ĐỦ=============
outFileDatasetCSV = "D:\lequangnhu\\bluekeep_datasetCSV.csv"
outfilePhanCumTXT = open('D:\lequangnhu\\blukeep_phancumTXT.txt','w')

#PATH PHẢI cùng VỚI ĐƯỜNG DẪN và cùng Tên file đã phân cụm Mà Ta KHAI BÁO Ở FILE MAIN
outFilePhanCumCSV = "D:\lequangnhu\\bluekeep_phancumCSV.csv"

#==========còn lại bên dưới chưa cần q tâm CHẠY ĐƯỢC là thành công bước đầu====================

#declare file and openfile DATA SET
csvfile1=open(outFileDatasetCSV,'w', newline='')
#create object CSV
objDataset=csv.writer(csvfile1)
objDataset.writerow(['time', 'packetlength', 'payloadlength'])


#declare file and openfile PHAN CUM
csvfile2=open(outFilePhanCumCSV,'w', newline='')
#create object CSV
obj=csv.writer(csvfile2)

obj.writerow(['time', 'packetlength', 'payloadlength'])

# outfileDataset.write("Point "+ "\t" + " time"+ "\t" +"totallength "+ "\t" +" payloadlength")

goi1 = list()
goi2 = list()
goi3 = list()
goi4 = list()
port_no_list = list()
port_list = list()
global_i = 0
no_list = list()
goi_all = list()
goi_all_dataset = list()
#--------------------------------------------------

def render_csv_row(pkt_sh, pkt_sc, fh_csv, dem1):
    global dem

    """Write one packet entry into the CSV file.
    pkt_sh is the PyShark representation of the packet
    pkt_sc is a 'bytes' representation of the packet as returned from
    scapy's RawPcapReader
    fh_csv is the csv file handle
    """
    global global_i
    temp=""
    ether_pkt_sc = Ether(pkt_sc)
    if ether_pkt_sc.type != 0x800:
        print('Ignoring non-IP packet')
        return False

    ip_pkt_sc = ether_pkt_sc[IP]       # <<<< Assuming Ethernet + IPv4 here
    proto = ip_pkt_sc.fields['proto']
    if proto == 17:
        udp_pkt_sc = ip_pkt_sc[UDP]
        l4_payload_bytes = bytes(udp_pkt_sc.payload)
        l4_proto_name = 'UDP'
        l4_sport = udp_pkt_sc.sport
        l4_dport = udp_pkt_sc.dport
    elif proto == 6:
        tcp_pkt_sc = ip_pkt_sc[TCP]
        l4_payload_bytes = bytes(tcp_pkt_sc.payload)
        l4_proto_name = 'TCP'
        l4_sport = tcp_pkt_sc.sport
        l4_dport = tcp_pkt_sc.dport

    else:
        # Currently not handling packets that are not UDP or TCP
        print('Ignoring non-UDP/TCP packet')
        return False
    pair_port = str(l4_sport)+"_"+str(l4_dport)
    re_pair_port = str(l4_dport)+"_"+str(l4_sport)
    if pair_port not in port_list:
        if re_pair_port in port_list:
            pos = port_list.index(re_pair_port)+1
            port_list.insert(pos,pair_port)
            port_no_list.append(pair_port)
            port_no_list.append(pkt_sh.no)
        else:
            port_list.append(pair_port)
            port_no_list.append(pair_port)
            port_no_list.append(pkt_sh.no)      
    elif pkt_sh.no not in port_no_list:
        pos = port_no_list.index(pair_port)+1
        port_no_list.insert(pos,pkt_sh.no)
    #print(port_list)
    #print(port_no_list)
    # Each line of the CSV has this format
    fmt = '{0},{1},{2}({3}),{4},{5}:{6},{7}:{8},{9},{10}'
    #       |   |   |   |    |   |   |   |   |   |   |
    #       |   |   |   |    |   |   |   |   |   |   o-> {10} L4 payload hexdump
    #       |   |   |   |    |   |   |   |   |   o-----> {9}  total pkt length
    #       |   |   |   |    |   |   |   |   o---------> {8}  dst port
    #       |   |   |   |    |   |   |   o-------------> {7}  dst ip address
    #       |   |   |   |    |   |   o-----------------> {6}  src port
    #       |   |   |   |    |   o---------------------> {5}  src ip address
    #       |   |   |   |    o-------------------------> {4}  text description
    #       |   |   |   o------------------------------> {3}  L4 protocol
    #       |   |   o----------------------------------> {2}  highest protocol
    #       |   o--------------------------------------> {1}  time
    #       o------------------------------------------> {0}  frame number


    # Example:
    # 1,0.0,DNS(UDP),Standard query 0xf3de A www.cisco.com,192.168.1.116:57922,1.1.1.1:53,73,f3de010000010000000000000377777705636973636f03636f6d0000010001
    
    #print(bytes(tcp_pkt_sc).hex())
    goi_all.append(pkt_sh.no)
    goi_all.append(fmt.format(pkt_sh.no,pkt_sh.time,pkt_sh.protocol,l4_proto_name,pkt_sh.info.replace(","," "),pkt_sh.source,l4_sport,pkt_sh.destination,l4_dport,pkt_sh.length,l4_payload_bytes.hex()))

    global daylaTLSv1handshake
    if(pkt_sh.protocol.find('ICMP') != -1  or pkt_sh.protocol.find('UDP') != -1 ):# tìm và loại bỏ gói tin ping
        return True  
    # để bắt đầu thu thập lưu lượng thì ta phải xác định được, có tồn tại quá trình bắt tay của TSL của dịch vụ remote desktop?
    elif((pkt_sh.info.find('Client Hello') != -1 or pkt_sh.info.find('Server Hello') != -1 ) and pkt_sh.protocol.find('TLSv1') != -1):
        daylaTLSv1handshake = True  # đây chính là quá trình handshake của TLS                                                                                                                                                                                                                       
    if(daylaTLSv1handshake == True):# nếu có quá trình bắt tay của TLS(remote desktop chạy giao thức này)thì mới lấy lưu lượng
        if(l4_dport == 3389 or l4_sport == 3389 or pkt_sh.info.find('[TCP segment of a reassembled PDU]') != -1):# lấy các tập tin có đặc điểm này
            if(pkt_sh.info.find('Client Hello') != -1 and dem == 0):# lấy địa chỉ ip của máy gửi gói tin co info: client hello
                ipMayTanCong = str(pkt_sh.source)
                outfile_ipmaytancong.write(ipMayTanCong)
                dem += 1
            #write file csv DATASET
            objDataset.writerow([pkt_sh.time, pkt_sh.length, len(l4_payload_bytes)])

            # đếm 10 gói thì ta lấy 1 gói cuối cùng(xem như 1 point dữ liệu gồm 10 gói)
            if(dem1 % 10 == 0):
                if len(l4_payload_bytes) == 0: # check length payload(có empty không?) để lưu vào file là 0, tránh việc nó không lưu gì cả. Dẫn đến sai ở các bước dưới

                    # gộp các thông tin cần lấy như (time, total length, payload(headerlenght)) vào biến tạm
                    temp = str(str(pkt_sh.time) + "\t" + str(pkt_sh.length) +"\t" + str(0) + str(IP))

                    #write file csv PHÂN CỤM
                    obj.writerow([pkt_sh.time, pkt_sh.length, 0])

                    #write file txt PHÂN CỤM
                    outfilePhanCumTXT.write("Point " + str(int(dem1/10)) + ": " + " " + temp + "\n")

                else:

                    # gộp các thông tin cần lấy như (time, total length, payload(headerlenght)) vào biến tạm
                    temp = str(str(pkt_sh.time) + "\t" + str(pkt_sh.length) +"\t" + str(len(l4_payload_bytes)))

                    #write file CSV PHÂN CỤM
                    obj.writerow([pkt_sh.time, pkt_sh.length, len(l4_payload_bytes)])

                    #write file TXT PHÂN CỤM
                    outfilePhanCumTXT.write("Point " + str(int(dem1/10)) + ": " + " " + temp + "\n")
        
        
        
    return True
    #--------------------------------------------------

def pcap2csv(in_pcap, out_csv, out_gomcum):

    

    """Main entry function called from main to process the pcap and
    generate the csv file.
    in_pcap = name of the input pcap file (guaranteed to exist)
    out_csv = name of the output csv file (will be created)
    This function walks over each packet in the pcap file, and for
    each packet invokes the render_csv_row() function to write one row
    of the csv.
    """
    #outfileDataset = open('D:/dataset_blukeep.txt','w')
    
    frame_num = 0
    ignored_packets = 0
    with open(out_csv, 'a') as fh_csv:
        fmt = '{0},{1},{2},{3},{4},{5},{6},{7}'
        print(fmt.format("No.",                             # {0}
                     "Time",                                # {1}
                     "Protocol",                            # {2}
                     "Info",                                # {3}
                     "Source IP and port",                  # {4}
                     "Dest IP and port",                    # {5}
                     "Length",                              # {6}
                     "Payload in Bytes"),                    # {7}
          file=fh_csv)
        # Open the pcap file with scapy's RawPcapReader, and iterate over
        # each packet. In each iteration get the PyShark packet as well,
        # and then call render_csv_row() with both representations to generate
        # the CSV row.
        old_count = -1
        while 1:
            time.sleep(3)
            count = 0
            # Open the pcap file with PyShark in "summary-only" mode, since this
            # is the mode where the brief textual description of the packet (e.g.
            # "Standard query 0xf3de A www.cisco.com", "Client Hello" etc.) are
            # made available.
            
            for (pkt_scapy, _) in RawPcapReader(in_pcap):
                count += 1
            print("Count " + str(count))
            if(old_count==count): break
            else: old_count = count
            pcap_pyshark = pyshark.FileCapture(in_pcap, only_summaries=True)
            pcap_pyshark.load_packets()
            pcap_pyshark.reset()
            dem1 = 1
            for (pkt_scapy, _) in RawPcapReader(in_pcap):
                try:
                    pkt_pyshark = pcap_pyshark.next_packet()
                    if(int(pkt_pyshark.no)<frame_num):
                        continue
                    else:
                        frame_num += 1
                        dem1 += 1
                        #print("Frame " + str(frame_num))
                        if not render_csv_row(pkt_pyshark, pkt_scapy, fh_csv, dem1):
                            
                            ignored_packets += 1
                except StopIteration:
                    # Shouldn't happen because the RawPcapReader iterator should also
                    # exit before this happens.
                    break
        """
        for i in range(len(goi4)):
            byte_out = int(goi1[i].split("|")[0]) + int(goi2[i].split("|")[0]) + int(goi3[i].split("|")[0]) + int(goi4[i].split("|")[0])
            time_out = (float(goi4[i].split("|")[1]) - float(goi3[i].split("|")[1])) + (float(goi3[i].split("|")[1]) - float(goi2[i].split("|")[1])) + (float(goi2[i].split("|")[1]) - float(goi1[i].split("|")[1]))
            header_len = goi1[i].split("|")[2]
            outfile.write("Point "+str(i)+": "+str(byte_out)+"\t"+str(time_out)+"\t"+header_len+"\n")
        """
        fmt_dataset = '{0},{1},{2},{3}'
        print(fmt_dataset.format("Point",                    # {0}
                    "Bytes",                                 # {1}
                    "Time",                                  # {2}
                    "Hlen"),                                 # {3}      
                    file=outfile)
        j=0
        point=0
        #print(len(goi_all))
        #print(port_list)
        #print(port_no_list)
        while j < len(port_list)-1:
            sum1_1 = int(port_list[j].split("_")[0])
            sum1_2 = int(port_list[j].split("_")[1])
            sum2_1 = int(port_list[j+1].split("_")[0])
            sum2_2 = int(port_list[j+1].split("_")[1])
            time_dataset_max = 0.0
            goimin = 99999999999999999999999999999999999
            time_dataset_min = 9999999999999999999999999.0
            hlen_dataset = 0
            byte_dataset = 0
            if sum1_1==sum2_2 and sum1_2==sum2_1:
                if(j == len(port_list)-2):
                    list1 = port_no_list[port_no_list.index(port_list[j]):]
                    list2 = port_no_list[port_no_list.index(port_list[j+1]):len(port_no_list)]
                else:
                    list1 = port_no_list[port_no_list.index(port_list[j]):]
                    list2 = port_no_list[port_no_list.index(port_list[j+1]):]
                temp=1
                while temp<len(list1):
                    if(list1[temp].find('_')<0):
                        print(goi_all[goi_all.index(list1[temp])+1],file=fh_csv)
                        byte_dataset+=len(goi_all[goi_all.index(list1[temp])+1].split(",")[7])/2
                        if(float(goi_all[goi_all.index(list1[temp])+1].split(",")[1])>=time_dataset_max):
                            time_dataset_max = float(goi_all[goi_all.index(list1[temp])+1].split(",")[1])
                        if float(goi_all[goi_all.index(list1[temp])+1].split(",")[1])<=time_dataset_min:
                            time_dataset_min = float(goi_all[goi_all.index(list1[temp])+1].split(",")[1])
                        if(int(goi_all[goi_all.index(list1[temp])+1].split(",")[0])<=goimin):
                            hlen_dataset = int(goi_all[goi_all.index(list1[temp])+1].split(",")[6])
                        temp+=1
                    else:
                        break

                temp=1
                while temp<len(list2):
                    if(list2[temp].find('_')<0):
                        print(goi_all[goi_all.index(list2[temp])+1],file=fh_csv)
                        byte_dataset+=len(goi_all[goi_all.index(list2[temp])+1].split(",")[7])/2
                        if(float(goi_all[goi_all.index(list2[temp])+1].split(",")[1])>=time_dataset_max):
                            time_dataset_max = float(goi_all[goi_all.index(list2[temp])+1].split(",")[1])
                        if float(goi_all[goi_all.index(list2[temp])+1].split(",")[1])<=time_dataset_min:
                            time_dataset_min = float(goi_all[goi_all.index(list2[temp])+1].split(",")[1])
                        if(int(goi_all[goi_all.index(list2[temp])+1].split(",")[0])<=goimin):
                            hlen_dataset = int(goi_all[goi_all.index(list2[temp])+1].split(",")[6])
                        temp+=1
                    else:
                        break
                print(fmt_dataset.format(point,byte_dataset,str(time_dataset_max-time_dataset_min),hlen_dataset),file=outfile)
                point+=1
                j+=2
            else:
                temp=1
                list1 = port_no_list[port_no_list.index(port_list[j]):]
                while temp<len(list1):
                    if(list1[temp].find('_')<0):
                        print(goi_all[goi_all.index(list1[temp])+1],file=fh_csv)
                        byte_dataset+=len(goi_all[goi_all.index(list1[temp])+1].split(",")[7])/2
                        if(float(goi_all[goi_all.index(list1[temp])+1].split(",")[1])>=time_dataset_max):
                            time_dataset_max = float(goi_all[goi_all.index(list1[temp])+1].split(",")[1])
                        if float(goi_all[goi_all.index(list1[temp])+1].split(",")[1])<=time_dataset_min:
                            time_dataset_min = float(goi_all[goi_all.index(list1[temp])+1].split(",")[1])
                        if(int(goi_all[goi_all.index(list1[temp])+1].split(",")[0])<=goimin):
                            hlen_dataset = int(goi_all[goi_all.index(list1[temp])+1].split(",")[6])
                        temp+=1
                    else:
                        break
                print(fmt_dataset.format(point,byte_dataset,str(time_dataset_max-time_dataset_min),hlen_dataset),file=outfile)
                point+=1
                j+=1

        print(port_list)
    print('{} packets read, {} packets not written to CSV'.
          format(frame_num, ignored_packets))
    
    
    #outfilePhanCumTXT.flush()# marker changed file
    #outfilePhanCumTXT.tell()
    #outfilePhanCumTXT.seek(0) #dua con tro chi vi ve vi tri dau file
    outfilePhanCumTXT.close()# close file
    #os.fsync()# marker changed file
    csvfile1.close()
    csvfile2.close()
    outfile_ipmaytancong.close()

    
#--------------------------------------------------

# def command_line_args():
#     """Helper called from main() to parse the command line arguments"""

#     parser = argparse.ArgumentParser()
#     parser.add_argument('--pcap', metavar='<input pcap file>',
#                         help='pcap file to parse', required=True)
#     parser.add_argument('--csv', metavar='<output csv file>',
#                         help='csv file to create', required=True)
#     args = parser.parse_args()
#     return args
# #--------------------------------------------------

# def main():
#     """Program main entry"""
#     args = command_line_args()

#     """
#     if not os.path.exists(args.pcap):
#         print('Input pcap file "{}" does not exist'.format(args.pcap),
#               file=sys.stderr)
#         sys.exit(-1)
#     """

#     if os.path.exists(args.csv):
#         print('Output csv file "{}" already exists, '
#               'won\'t overwrite'.format(args.csv),
#               file=sys.stderr)
#         sys.exit(-1)
#     pcap2csv(args.pcap, args.csv)
# #--------------------------------------------------

# if __name__ == '__main__':
#     main()
    