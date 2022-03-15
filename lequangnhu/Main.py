#====ĐẦU TIÊN: ĐỌC 6 DÒNG COMMENT DƯỚI CÙNG TRC ĐỂ CÓ CÁI NHÌN TỔNG QUAN.
#====SAU ĐÓ BẮT ĐẦU ĐỌC TỪ hàm ===def main()====
#======BƯỚC ĐẦU TIÊN PHẢI LÀM CHO CTRINH CHẠY ĐƯỢC(hướng dẫn bên dưới(đổi đường dẫn file theo Hướng dẫn là xong)) =====
from convertPcapToCsv import pcap2csv
from PhatHienTanCong import detectBluekeepDuaVaoFilePhanCum
from PhatHienTanCong import dohoa
import csv
import time
#from ListenAndExportPcap import listen

count = 0

# chỗ này do tên hàm pcap2csv nhìn ko rõ ý nên mới chèn vào 1 hàm khác cho dễ hiểu
def convertPcapToCSV(pathFilePcap, path_out_CSV, path_phancum_csv):
    pcap2csv(pathFilePcap, path_out_CSV, path_phancum_csv)


def main():
    # get file pcap
    # getFilePcap()
    global count
    while(1):
        count += 1

        #===========STEP 1: listen and export PCAP==========================
        #pathFilePcap = 'D:\DESKTOP\HocMonThayThe\AnNinhMang\code\DoAnCuoiMon\\fileLDump'+str(count)+'.pcap'
        #listen(pathFilePcap)
        
        # file này bắt buột phải có dữ liệu sẵn(đã bắt gói). TẤT CẢ ĐƯỜNG DẪN ở các file khác cũng PHẢI ĐỂ CÙNG 1 THƯ MỤC(đổi path rồi cứ đọc xuống dưới tiếp!)
        pathFilePcap = 'D:\lequangnhu\\cvebluekeep.pcap'

        #==========STEP 2: read file PCAP and export file datatho.csv, dataset.csv, phancum.csv, phancum.txt==========
        
        #=========MỤC ĐÍCH CỦA CÁC FILE TRÊN================
        # datatho.csv, dataset.csv : 2 file này xuất ra.
        # phancum.csv: file này để làm đầu vào chạy đc ctrinh đồ họa
        # phancum.txt: file này để chạy chương trình phát hiện tấn công
        
        # convert filepcap to csv
        # declare file and openfile
        csvfile='D:\lequangnhu\\bluekeep_datatho'+ str(count) +'.csv'
        csvphancum='D:\lequangnhu\\bluekeep_phancum'+ str(count) +'.csv'
        
        #open file pcap and export file datatho.csv dataset.csv phancum.csv phancum.txt
        convertPcapToCSV(pathFilePcap, csvfile, csvphancum)

        
        #=========STEP 3: DETECT ATTACK BASE ON phancum.TXT===========================
        detectBluekeepDuaVaoFilePhanCum()

        
        #==========STEP 4: CREATE GRAPH BASE ON FILE phancum.CSV==========
        dohoa()
        
    

# thuật toán chạy như sau:
# chạy vòng lặp while (1)
# bước 1 : khai báo file thay đổi tên file theo count ++
# bước 2: gọi hàm lắng nghe trên cổng VMW(interface chỗ subprocess máy tao là -i 2), với gói số lượng 1000 gói 1 lần nghe và lưu vào file ở trên.
# bước 3: gọi hàm chuyển file pcap sang file csv, lọc dữ liệu file csv để tạo thành file dataset(file csv) và gôm các gói tin tạo thành các điểm dữ liệu(lỗ hỏng blue: 10 gói 1 điểm, tùy theo)
# bước 4: phân cụm và đồ họa dựa vào file đã gôm các điểm dữ liệu
main()