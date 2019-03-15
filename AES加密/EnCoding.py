# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     EnCoding
   Description :   AES工作模式
   Author :        陈生
   date：          2019/3/8
-------------------------------------------------
   Change Activity:
                   2019/3/8:
-------------------------------------------------
"""
# 本文件将实现5中加密模式（CBC、ECB、CTR、OCF、CFB）
# 1.电码本模式（Electronic Codebook Book (ECB)）；
# 2.密码分组链接模式（Cipher Block Chaining (CBC)）；
# 3.计算器模式（Counter (CTR)）；
# 4.密码反馈模式（Cipher FeedBack (CFB)）；
# 5.输出反馈模式（Output FeedBack (OFB)）。
# 异或 相同为0 不同为1

datalen = 16  # 数据长度
enclen = 4   # 分段长度
encTable = [0,1,0,1] # 加密公式表
data=[1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1]
ciphertext= [-1 for i in range(16)]; # 密文

# 切片加密函数
def encode(arr):
    for i in range(enclen):
        arr[i] = arr[i] ^ encTable[i]

# ECB加密，分4端，每次提取加密一段，分四次进行。
def ECB(arr):
    # 分段
    Segment = [[0]*4 for i in range(4)]  # 密文块
    dataCount = 0
    for i in range(4):
        for j in range(4):
            Segment[i][j] = arr[dataCount]
            dataCount += 1

    dataCount = 0
    for i in range(0,16,4):
        r = (int)(i / enclen)   # 行
        encQue = [-1 for i in range(enclen)]   # 提取当前加密片段
        for j in range(enclen):
           encQue[j] = Segment[r][j]

        encode(encQue)      # 进行异或加密
        # 接下来加入密文
        for k in range(enclen):
            ciphertext[dataCount] = encQue[k]
            dataCount += 1

    print('通过ECB加密后得到的密文为')
    print(ciphertext)
    print('------------------------------------------------')

# CBC加密 通过增加一个初始向量，在加密过程中双重加密
def CBC(arr):
    # 分段（二维数组）存放明文
    Segment = [[0] * 4 for i in range(4)]  # 密文块
    dataCount = 0
    for i in range(4):
        for j in range(4):
            Segment[i][j] = arr[dataCount]
            dataCount += 1
    dataCount = 0

    # 定义初始向量（IV）
    initVector = [1,0,1,0]

    # 分段处理Segment
    for i in range(0, 16, 4):
        r = (int)(i / enclen)  # 行
        # 通过IV加密
        for j in range(enclen):
            Segment[r][j] = Segment[r][j] ^ initVector[j]

        # 提取当前加密片段
        encQue = [-1 for i in range(enclen)]
        for k in range(enclen):
            encQue[k] = Segment[r][k]

        encode(encQue)

        # 重新初始化IV
        for l in range(enclen):
            initVector[l] = encQue[l]

        # 放入密文段
        for m in range(enclen):
            ciphertext[dataCount] = encQue[m]
            dataCount += 1

    print('通过CBC加密后得到的密文为')
    print(ciphertext)
    print('------------------------------------------------')

# CTR加密 计算器模式
def CTR(arr):
    # 分段（二维数组）存放明文
    Segment = [[0] * 4 for i in range(4)]
    dataCount = 0
    for i in range(4):
        for j in range(4):
            Segment[i][j] = arr[dataCount]
            dataCount += 1
    dataCount = 0

    # 算子表与计数君
    initVector = [ [1,0,1,0],[1,1,1,1],[0,0,1,1],[0,1,0,1] ]
    count = 0;
    # 分段处理Segment
    for i in range(0, 16, 4):
        r = (int)(i / enclen)  # 行
        # 通过算子表加密
        for j in range(enclen):
            Segment[r][j] = Segment[r][j] ^ initVector[count][j]
        count += 1

        # 提取当前加密片段
        encQue = [-1 for i in range(enclen)]
        for k in range(enclen):
            encQue[k] = Segment[r][k]

        encode(encQue)

        # 放入密文段
        for m in range(enclen):
            ciphertext[dataCount] = encQue[m]
            dataCount += 1

    print('通过CTR加密后得到的密文为')
    print(ciphertext)
    print('------------------------------------------------')

# CFB密码反馈模式
def CFB(arr):
    # 分段（二维数组）存放明文
    Segment = [[0] * 4 for i in range(4)]
    dataCount = 0

    for i in range(4):
        for j in range(4):
            Segment[i][j] = arr[dataCount]
            dataCount += 1
    dataCount = 0

    initVector = [0,1,0,1]

    for i in range(0, 16, 4):
        r = (int)(i / enclen)  # 行

        # 不断对IV进行加密
        encode(initVector)

        # 提取当前需加密片段
        encQue = [-1 for i in range(enclen)]
        for k in range(enclen):
            encQue[k] = Segment[r][k]

        # 通过与 加密后的IV 进行异或
        for j in range(enclen):
            encQue[j] = encQue[j] ^ initVector[j]

        # 重新初始化IV
        for l in range(enclen):
            initVector[l] = encQue[l]

        # 放入密文段
        for m in range(enclen):
            ciphertext[dataCount] = encQue[m]
            dataCount += 1

    print('通过CFB加密后得到的密文为')
    print(ciphertext)
    print('------------------------------------------------')

# 输出反馈模式
def OFB(arr):
    # 分段（二维数组）存放明文
    Segment = [[0] * 4 for i in range(4)]
    dataCount = 0

    for i in range(4):
        for j in range(4):
            Segment[i][j] = arr[dataCount]
            dataCount += 1
    dataCount = 0

    initVector = [0,1,0,1]

    for i in range(0, 16, 4):
        r = (int)(i / enclen)  # 行

        # 不断对IV进行加密
        encode(initVector)

        # 提取当前需加密片段
        encQue = [-1 for i in range(enclen)]
        for k in range(enclen):
            encQue[k] = Segment[r][k]

        # 通过与 加密后的IV 进行异或
        for j in range(enclen):
            encQue[j] = encQue[j] ^ initVector[j]

        # 放入密文段
        for m in range(enclen):
            ciphertext[dataCount] = encQue[m]
            dataCount += 1


    print('通过OFB加密后得到的密文为')
    print(ciphertext)
    print('------------------------------------------------')

if __name__== "__main__":
    print('原来明文为')
    print(data)
    print('-----------------------分割----------------------')
    ECB(data)
    CBC(data)
    CTR(data)
    CFB(data)
    OFB(data)
