import ctypes
import io
import struct
from peachpy import *
from peachpy.x86_64 import *
# MMX指令集算法
# def pmaddwd(mm0:int,mm1:int):
#     #因为有符号需要struct转化一下
#     mm0 = mm0.to_bytes(8,'big')
#     mm1 = mm1.to_bytes(8,'big')
#     x = struct.unpack("<hhhh",mm0)
#     y = struct.unpack("<hhhh",mm1)
#     tmp0 = x[0]*y[0]+x[1]*y[1]
#     tmp1 = x[2]*y[2]+x[3]*y[3]
#     #重新打包回无符号数
#     tmp0 = struct.unpack("<I",struct.pack("<i",tmp0))[0]
#     tmp1 = struct.unpack("<I",struct.pack("<i",tmp1))[0]
#     return tmp0 << 32 + tmp1
# def paddw(mm0,mm1):
#     x3 = (mm0 & 0xFFFF000000000000)>>48
#     x2 = (mm0 & 0x0000FFFF00000000)>>32
#     x1 = (mm0 & 0x00000000FFFF0000)>>16
#     x0 = (mm0 & 0x000000000000FFFF)
#     y3 = (mm1 & 0xFFFF000000000000)>>48
#     y2 = (mm1 & 0x0000FFFF00000000)>>32
#     y1 = (mm1 & 0x00000000FFFF0000)>>16
#     y0 = (mm1 & 0x000000000000FFFF)
#     tmp3 = (x3+y3) &0xFFFF #防止溢出
#     tmp2 = (x2+y2) &0xFFFF #防止溢出
#     tmp1 = (x1+y1) &0xFFFF #防止溢出
#     tmp0 = (x0+y0) &0xFFFF #防止溢出
#     result = (tmp3<<48)+(tmp2<<32)+(tmp1<<16)+tmp0
#     return result
# def paddd(mm0,mm1):
#     x1 = (mm0 & 0xFFFFFFFF00000000)>>32
#     x0 = (mm0 & 0x00000000FFFFFFFF)
#     y1 = (mm1 & 0xFFFFFFFF00000000)>>32
#     y0 = (mm1 & 0x00000000FFFFFFFF)
#     tmp1 = (x1+y1) &0xFFFFFFFF #防止溢出
#     tmp0 = (x0+y0) &0xFFFFFFFF #防止溢出
#     result = tmp1<<32+tmp0
#     return result
# def pslld(mm0,n) -> int:
#     x1 = (mm0 & 0xFFFFFFFF00000000)>>32
#     x0 = (mm0 & 0x00000000FFFFFFFF)
#     x1 = (x1 << n) & 0xFFFFFFFF #防止溢出
#     x0 = (x0 << n) & 0xFFFFFFFF #防止溢出
#     result = x1<<32+x0
#     return result
# def psrld(mm0,n):
#     x1 = (mm0 & 0xFFFFFFFF00000000)>>32
#     x0 = mm0 & 0xFFFFFFFF
#     x1 >>= n
#     x0 >>= n
#     result = x1<<32+x0
#     return result
#解密函数
class Dencypter:
    
    def __init__(self) -> None:
        data = Argument(ptr(uint64_t))
        len = Argument(int32_t)
        with Function("Tohash",(data,len),uint32_t) as function_tohash:
            #准备工作
            looptimes = GeneralPurposeRegister32()
            datap = GeneralPurposeRegister64()
            LOAD.ARGUMENT(looptimes,len)
            SHR(looptimes,3)
            LOAD.ARGUMENT(datap,data)
            PXOR(mm0,mm0)
            PXOR(mm1,mm1)
            PXOR(mm2,mm2)
            MOV(eax,0xA35793A7)
            MOVD(mm3,eax)
            PUNPCKLDQ(mm3,mm3)
            with Loop() as loop:
                MOVQ(mm1,qword[datap])
                PADDW(mm2,mm3)
                PXOR(mm1,mm2)
                PADDW(mm0,mm1)
                MOVQ(mm1,mm0)
                PSLLD(mm0,3)
                PSRLD(mm1,0x1D)
                POR(mm0,mm1)
                ADD(datap,0x8)
                CMP(looptimes,0)
                JGE(loop.begin)
            MOVQ(mm1,mm0)
            PSRLQ(mm1,0x20)
            PMADDWD(mm0,mm1)
            MOVD(eax,mm0)
            EMMS()
            RETURN(eax)
        self._asm_Tohash = function_tohash.finalize(peachpy.x86_64.abi.detect()).encode().load()
dencrypter = Dencypter()
def Hash(data,len):
    if len < 8:
        return 0
    return dencrypter._asm_Tohash(data,len)
# def Hash(data,len) -> bytes:
#     if len < 8:
#         return struct.pack("<I",0)
#     looptimes = len>>3
#     #准备工作
#     mm0=0
#     mm1=0
#     mm2=0
#     # key = 0xA35793A7
#     mm3 = 0xA35793A7A35793A7 #punpckldq
#     #开始循环
#     for i in range(looptimes):
#         mm1 = struct.unpack("<Q",bytes(data[i*8:i*8+8]))[0]
#         mm2 = paddw(mm2,mm3)
#         mm1 = mm1 ^ mm2
#         mm0 = paddw(mm0,mm1)
#         mm1 = mm0
#         mm0 = pslld(mm0,3) #pslld 逻辑左移
#         mm1 = psrld(mm1,0x1D)
#         mm0 = mm1|mm0
#     mm1 = mm0 >> 32
#     print(mm0,mm1)
#     return pmaddwd(mm0,mm1)
# def dencrypt(data,len,hash):
#     looptimes = len >> 3
#     if looptimes == 0:
#         return
#     #准备工作
#     key1 = 0xA73C5F9D
#     key2 = 0xCE24F523
#     key3 = ((len+hash) & 0xFFFFFFFF)^0xFEC9753E #加法防溢出
#     mm7 = key1 << 32 + key1
#     mm6 = key2 << 32 + key2
#     mm5 = key3 << 32 + key3
#     result = bytes()
#     for i in range(looptimes):
#         mm7 = paddd(mm7,mm6)
#         mm7 ^= mm5
#         mm0 = struct.unpack("<Q",bytes(data[i*8:i*8+8]))[0]
#         mm0 ^=mm7
#         mm5 = mm0
#         result += struct.pack("<Q",mm0)
#     return result.decode('ascii')
#类定义
class FilePackVer:
    def __init__(self,hfile:io.BufferedReader) -> None:
        #获取文件大小
        hfile.seek(0,2)
        filesize = hfile.tell()
        #指针放到FilePackVer结构体位置
        hfile.seek(filesize-0x1C,0)
        self.sign = hfile.read(0x10).decode("ascii")
        self.filecount = struct.unpack("<I",hfile.read(0x4))[0] #因为是小端数据需要转化
        self.entry = struct.unpack("<Q",hfile.read(0x8))[0]
class HashData:
    def __init__(self,hfile:io.BufferedReader) -> None:
        #获取文件大小
        hfile.seek(0,2)
        filesize = hfile.tell()
        #指针放到HashData结构体位置
        hfile.seek(filesize-0x440,0)
        d = bytearray(hfile.read(0x440)) #转化为字节数组方便切片和修改
        #数据的设置
        if struct.unpack("<I",bytes(d[0x124:0x128]))[0] > 8 or struct.unpack("<I",bytes(d[0x124:0x128]))[0] < 0:
            for i in range(0x124,0x128):
                d[i]=struct.pack('>x',0)
        #读取+0x24之后的256位数据
        data = d[0x24:0x124]
        self.hash = Hash((ctypes.c_uint64 * len(data))(*data),256) & 0x0FFFFFFF
        # self.sign = dencrypt(d[0:0x20],0x20,self.hash)
        self.HashVerSize = struct.unpack("<I",bytes(d[0x20:0x24]))[0]
#暂留一个HashVer结构体 可以在打包的时候使用
class HashVer:
    def __init__(self,hfile,size) -> None:
        pass
packname = input()
hfile = open(packname,"rb")
#创建FilePackVer结构体
filepackhead = FilePackVer(hfile)
hashdata = HashData(hfile)
if  hashdata.sign != "8hr48uky,8ugi8ewra4g8d5vbf5hb5s6":
    print("HashData验证失败")
    exit(0)

#HashVer里的数据对解包并不重要 直接略过不按照程序一样去读取了


hfile.close()