from AES128 import AES128 as AES
import math
import re
import wx
def asi_to_bin(s):
    list_h = []
    for c in s:
        list_h.append('{:08b}'.format(ord(c)))
    return ''.join(list_h)

def AESEN(p,k):
    encrypt=AES(p,k)
    encrypt.run_encryption()
    return ''+asi_to_bin(encrypt.get_result())

def AESDE(c,k):
    decrypt=AES(c,k)
    decrypt.run_decryption()
    return ''+asi_to_bin(decrypt.get_result())

def bin_to_asi(s):
    list_h=[]
    for a in range(0,16):
        i=a*8
        list_h.append(chr(int(str(s[i:i+8]),2)))
    return ''.join(list_h)

def XOR(s1,s2):
    string=''
    for i in range(128):
        string+=str(int(s1[i])^int(s2[i]))
    return string

def addcount(count):
    temp=int(count,2)
    temp=(temp+1) % 2**128
    count='{:0128b}'.format(temp)
    return count

def empty_fill(string):
    empty_n=16-len(string)
    string=string.ljust(16,chr(0))
    string=asi_to_bin(string)
    fill_n=str(bin(empty_n*8))[2:]
    fill_n=fill_n.rjust(128,'0')
    string=XOR(string,fill_n)
    return string
    
    
def separation(data):
    data_lenth=len(data)
    if data_lenth%16==0:
        N=int(data_lenth/16)
        plainlist=[]
        for i in range(0,N):
            T=16*i
            plainlist.append((data[T:T+16]))
    else:
        N=int(data_lenth/16)+1
        plainlist=[]
        for i in range(0,N-1):
            T=16*i
            plainlist.append(data[T:T+16])
        plainlist.append(bin_to_asi(empty_fill(data[16*N-16:])))
    return plainlist
    

def CTR_EN(data,K,count_k,count_p):
    plainlist=separation(data)
    N=len(plainlist)
    cipher_list=[]
    count=AESEN(count_p,count_k)
    for i in range(1,N+1):
        step1=AESEN(count,K)
        step2=XOR(step1,asi_to_bin(plainlist[i-1]))
        cipher_list.append(bin_to_asi(step2))
        count=addcount(count)
    return ''.join(cipher_list)

def CTR_DE(cipher,K,count_k,count_p):
    cipher_list=separation(cipher)
    N=len(cipher_list)
    plain_list=[]
    count=AESEN(count_p,count_k)
    for i in range(1,N+1):
        step1=AESEN(count,K)
        step2=XOR(step1,asi_to_bin(cipher_list[i-1]))
        plain_list.append(bin_to_asi(step2))
        count=addcount(count)
    result=''.join(plain_list)
    return re.split("\x00|\x08",result)[0]



class windowClass(wx.Frame):
    def __init__(self,*args,**kwargs):
        super(windowClass,self).__init__(*args,**kwargs,size = (700, 400))
        self.basicGUI()

    def Encrypt(self,e):
        count_k=self.count_kText.GetValue()
        count_p=self.count_pText.GetValue()
        K=self.KText.GetValue()
        data=self.contentText.GetValue()
        self.contentText.SetValue(CTR_EN(data,K,count_k,count_p))

    def Decrypt(self,e):
        count_k=self.count_kText.GetValue()
        count_p=self.count_pText.GetValue()
        K=self.KText.GetValue()
        data=self.contentText.GetValue()
        self.contentText.SetValue(CTR_DE(data,K,count_k,count_p))
        
    def basicGUI(self):
        panel=wx.Panel(self)
        self.SetTitle('AES-CRTMODE')
        wx.StaticText(panel,-1,'计数器p',(120,70))
        wx.StaticText(panel,-1,'计数器k',(120,110))
        wx.StaticText(panel,-1,'密钥',(120,150))
        wx.StaticText(panel,-1,'内容',(120,190))
        self.count_pText=wx.TextCtrl(panel,pos=(220,70),size=(200,30),style = wx.TE_MULTILINE)
        self.count_kText=wx.TextCtrl(panel,pos=(220,110),size=(200,30),style = wx.TE_MULTILINE)
        self.KText=wx.TextCtrl(panel,pos=(220,150),size=(200,30),style = wx.TE_MULTILINE)
        self.contentText=wx.TextCtrl(panel,pos=(220,190),size=(200,100),style = wx.TE_MULTILINE)
        self.buttonEN = wx.Button(panel, label = '加密', pos = (480, 70), size = (80, 40))
        self.buttonDE = wx.Button(panel, label = '解密', pos = (480, 150), size = (80, 40))
        self.buttonEN.Bind(wx.EVT_BUTTON,self.Encrypt)
        self.buttonDE.Bind(wx.EVT_BUTTON,self.Decrypt)
        self.Show()

if __name__=='__main__':
    app=wx.App()
    windowClass(None)
    app.MainLoop()
