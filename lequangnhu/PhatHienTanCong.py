import pandas as pd
from sklearn.cluster import KMeans

infileipmaytancong = "D:\lequangnhu\ipmaytancong.txt"
fileipmaytancong = open(infileipmaytancong, "r")

outfilePhanCumTXT = 'D:\lequangnhu\\blukeep_phancumTXT.txt'
outFilePhanCumCSV = "D:\lequangnhu\\bluekeep_phancumCSV.csv"

#======================Phân Cụm theo 3 điểm dữ liệu là 1 cụm=========================

#=========KHAI BAO BIEN TOAN CUC================
i = 0
time_list = list()
lengthpacket_list = list()
lengthPayload_list = list()



infile = open(outfilePhanCumTXT,'r')
outfile = open('D:\lequangnhu\\bluekeep_danhlabelTXT.txt','w')

# read file dataset
data = infile.read()

#split lines sprate (rieng le)
arr_data = data.split("\n")
arr_data2 = data.split("\n")

#=====================================================
def danhNhan():
    for i in range( len(arr_data)-1):
        #split element each
        temp = arr_data[i].split(": ")[1]
        tmp = temp.split("\t")
        time_list.append(tmp[0])

        lengthpacket_list.append(tmp[1])
        lengthPayload_list.append(tmp[2])

    df = pd.DataFrame({
        'x': lengthpacket_list,
        'y': time_list,
        'z': lengthPayload_list
    })

    kmeans = KMeans(n_clusters=2)
    kmeans.fit(df)
    labels = kmeans.predict(df)
    for i in range(len(arr_data)-1):
        outfile.write(arr_data[i] + "\t" + str(labels[i]) + "\n")
        #print(labels[i])


#danhNhan()

# ======================  PHÁT HIỆN TẤN CÔNG VÀ THÔNG BÁO====================
import pandas as pd
from sklearn.cluster import KMeans
#thư viện Tô màu
from colorama import Fore, Back, Style


def detectBluekeepDuaVaoFilePhanCum():
    infile = open('D:\lequangnhu\\blukeep_phancumTXT.txt','r')
    outfile = open('D:\lequangnhu\\bluekeep_danhlabelTXT.txt','w')

    # read file dataset
    data = infile.read()

    #split lines sprate (rieng le)
    arr_data = data.split("\n")
    arr_data2 = data.split("\n")
    # phat hien tan cong
    arr_time_list = list()

    #tinh vi gom 3 point lam 1 cum
    for i in range( len(arr_data)-1):
        #split element each
        temp = arr_data[i].split(": ")[1]
        tmp = temp.split("\t")
        time_list.append(tmp[0])
        #print(type(tmp[0]))
        if(i % 2 != 0):#get packet co so le 1 3 5 7 9. vi gom 3 point la 1 cum
            arr_time_list.append(tmp[0])

    # tru time ra 
    for i in range(0, len(arr_time_list)-2):
        #lay goi 3 tru goi 1
        dem = float(arr_time_list[i + 2]) - float(arr_time_list[i])
        if(dem < 2):#neu time nho hon 2S ==> attack
            print(Fore.RED + " =============BLUE KEEP DETECT DOS ================")
            print(Fore.BLUE + "IP attack: " + fileipmaytancong.read())
            #infileipmaytancong
            print(Style.RESET_ALL + Fore.RESET) # reset lai màu
            break

#detectBluekeepDuaVaoFilePhanCum()

#===================Đồ Họa 3D==============================
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import pandas as pd
import numpy as np
import csv


def dohoa():
    df2 = pd.read_csv('D:\lequangnhu\\bluekeep_phancumCSV.csv')
    df2.head()

    #========= Tính số lượng dòng của file CSV trừ dòng title==========
    file = open("D:\lequangnhu\\bluekeep_phancumCSV.csv")
    reader = csv.reader(file)
    lines= len(list(reader))

    v = np.random.rand(lines - 1,4)
    v[:,3] = np.random.randint(0,2,size=lines - 1)
    df = pd.DataFrame(v, columns=['Feature1', 'Feature2','Feature3',"Cluster"])
    #print (df)

    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')
    x = df2['time']
    y = df2['packetlength']
    z = df2['payloadlength']

    ax.scatter(x,y,z, marker="s", c=df["Cluster"], s=40, cmap="RdBu")
    plt.show()

#dohoa()
