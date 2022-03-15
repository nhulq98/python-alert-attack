import subprocess
#import os
import time
#from HeThongCanhBaoAttack import convertPcapToCSV

# class Listen:
def listen(pathFilePcap):

    # Listen & write -> Pcap
    #pathFilePcap = 'D:\DESKTOP\HocMonThayThe\AnNinhMang\code\DoAnCuoiMon\\fileLDump'+str(count)+'.pcap'
    
    # -i 3: ethernet || -i 1: wifi || -i 2 virtual machine VMW 
    p = subprocess.Popen('D:\lequangnhu\\WinDump.exe  -i 2 -c 1000 -w ' + pathFilePcap, stdout=subprocess.PIPE, shell=True)
    
    #lines = os.popen("D:\DESKTOP\HocMonThayThe\AnNinhMang\code\DoAnCuoiMon\\WinDump.exe -i 2 -c 20 -w" + pathFilePcap)
    time.sleep(30) # Sleep 20s then kill subprocess

    # #listen alway!!
    subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=p.pid))



# def main():
#     #global count
#     listen()
listen("D:\lequangnhu\\cvebluekeep.pcap")