from tkinter import *
import pyfiglet
import time
from colorama import init, Fore
import sys
import socket
from datetime import datetime
import requests
import pymysql
import paramiko
import subprocess
import os
import tempfile
from termcolor import colored
from smb.SMBConnection import SMBConnection
import tkinter as tk
from PIL import ImageTk, Image
import threading
from threading import *
from tkinter import *
from tkinter.ttk import Progressbar
global ftp_vuln
ftp_vuln=0
global http_vuln
http_vuln=0
global ssh_vuln
ssh_vuln=0
global telnet_vuln
telnet_vuln=0
global smtp_vuln
smtp_vuln=0
global samba_vuln
samba_vuln=0
global mysql_vuln
mysql_vlun=0
global postgres_vuln
postgresql_vuln=0



window = Tk()

window.title("Welcome to Port Security Scanner by Mustafa Akbulut")

window.geometry('1000x1000')
my_label = Label(window, text = "PORT SECURITY SCANNER", fg = "Green",bg='gray', font = ("Helvetica bold", 32,)) # setting up the labels 
my_label.place(x=200,y=10)

#bg = PhotoImage(file = "back.png")


window.configure(background='gray')

lbl = Label(window, text="Enter the target hostname or ip:")
lbl.place(x=10,y=100)

ip = Entry(window,width=13)
ip.place(x=230,y=100)

#choice2 = Label(window, text="Exploit FTP: ")
#choice2.place(x=520,y=125)

#choice = Entry(window,width=10) 
#choice.place(x=600,y=125)

lbl2=Label(window,text="Enter the port or port range (21, 0-1000): ")
lbl2.place(x=10,y=150)

port1=Entry(window,width=10)
port1.place(x=290,y=150)
global radio_count
radio_count=0

def selected(value):
        
        global r
        #print("r.get = "+value)
        print("Value= "+value+" pb1= "+str(pb1['value'])+"\n")
        if value=="0" or pb1['value']<100:
                f3=open("logs.txt")
                text1.delete("1.0",tk.END)
                for i in f3.readlines():
                        
                        text1.insert(tk.END, "\n")
                        text1.insert(tk.END,i)
                f3.close()
        elif pb1['value']>=100:
                text1.delete("1.0",tk.END)
                if value=="ftp":
                        print("ohaaaaaa")
                        f3=open("ftp/ftp_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close()
                if value=="http":
                        f3=open("http/http_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close()
                if value=="http":
                        f3=open("https/https_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text.insert(tk.END,i)
                        f3.close()
                if value=="mysql":
                        f3=open("mysql/mysql_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close()
                if value=="postgresql":
                        f3=open("postgres/postgres_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close()
                if value=="netbios-ssn":
                        f3=open("smb/smb_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close()
                if value=="smtp":
                        f3=open("smtp/smtp_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close()
                if value=="ssh":
                        f3=open("ssh/ssh_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close()
                if value=="telnet":
                        f3=open("telnet/telnet_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close()                
                if value=="nfs":
                        f3=open("nfs/nfs_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close() 
                if value=="shell":
                        f3=open("remote_access/exec_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close()
                if value=="rmiregistry":
                        f3=open("rmi/rmi_vulns.txt")
                        for i in f3.readlines():
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END,i)
                        f3.close()
text1=tk.Text(window, height=40, width=60)

text1.place(x=500,y=200)
text1.tag_config('warning', background="yellow", foreground="red")

text1.tag_config('info', background="yellow", foreground="green")

text1.tag_config('found',foreground="blue")

global open_ports
open_ports=[]

def ip_or_hostname(ip):
        try:
                parts = ip.split('.')
                return len(parts) == 4 and all(0 <= int(part) < 256 for part in parts)
        except ValueError:
                return False # one of the 'parts' not convertible to integer
        except (AttributeError, TypeError):
                return False # `ip` isn't even a string


def is_ssh_open(host):
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                pass_list=["calvin","root","toor","msfadmin","password","password","Amx1234!","password","admin"]
                user_list=["root","root","root","msfadmin","administrator","NetLinx","administrator","amx","amx"]
                f3=open("logs.txt","a")
                f3.write("\nTrying to connect SSH with default credentials...\n")
                f3.write("-"*50)
                f3.close()
                for i in range(9):
                        username11=user_list[i]
                        password11=pass_list[i]
                        try:
                                ssh.connect(host, 22, username11,password11)
                        except paramiko.AuthenticationException:
                                #text1.insert(tk.END, "\n")
                                #text1.insert(tk.END, f"[!] Invalid credentials for {username11}:{password11}")                                
                                print("invalid credentials")
                        except socket.timeout:
                                return False
                        except paramiko.SSHException:
                                print("retrying with delay")
                                #text1.insert(tk.END, "\n")
                                #text1.insert(tk.END, "[*] Quota exceeded, retrying with delay...") 
                        # sleep for a minute
                                time.sleep(60)
                                return is_ssh_open(host)
                        else:
                        # connection was established successfully
                                serv_vulns['ssh']=1
                                f=open("ssh/ssh_vulns.txt","w")
                                f.write("[+] SSH protocol is using default credentials!!\n")
                                f.write(f"HOSTNAME: {host}\n\tUSERNAME: {username11}\n\tPASSWORD: {password11}")
                                f.close()
                                '''
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END, "[+]",'found')
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END, "SSH protocol is using default credentials!!",'warning')
                                text1.insert(tk.END, f"[+] Found combo:\n\tHOSTNAME: {host}\n\tUSERNAME: {username11}\n\tPASSWORD: {password11}",'warning')
                                '''
                                return True
global serv_vulns
serv_vulns={}


first=0
def scan_port(target,port):
        
        if port==1099:
                serviceName = socket.getservbyport(port, "tcp")
                serv_vulns[serviceName]=0   
                f3=open("logs.txt","a")
                f3.write("\nTrying to enumerate the JAVA RMI service...\n")
                f3.write("-"*50)
                f3.close()
                f2=open("rmi/rmi_output.txt","w")
                command=f"java -jar rmi/remote-method-guesser/target/rmg-4.3.0-jar-with-dependencies.jar enum 192.168.1.122 {port} > rmi/rmi_output.txt"
                #print("command "+command)
                #os.system(command)
                
                f2.close()
                subprocess.run(['java -jar rmi/remote-method-guesser/target/rmg-4.3.0-jar-with-dependencies.jar enum 192.168.1.122 1099 > rmi/rmi_output.txt'],shell=True)
                f2=open("rmi/rmi_output.txt")
                output=f2.readlines()
                f2.close()
                index2=0
                index=0
                for i in output:
                        print(i)
                        if "CVE" in i:
                                index2=output.index(i)
                        if "Vulnerable" in i:
                                serv_vulns[serviceName]=1
                                index=output.index(i)
                                f=open("rmi/rmi_vulns.txt","w")
                                for j in range(index2,index+1):
                                        output[j]=output[j].replace("[34m","")
                                        output[j]=output[j].replace("[0m","")
                                        output[j]=output[j].replace("[33m","")
                                        output[j]=output[j].replace("[31m","")
                                        output[j]=output[j].replace("","")
                                        f.write(output[j])
                                f.close()
                                
                global radio_count
                global align
                global align2
                if radio_count < 15:
                        if serv_vulns[serviceName]==0:
                                Radiobutton(window,text=serviceName,variable=r,value=serviceName,fg='black',command=threading2).place(x=10,y=align)
                        else:
                                Radiobutton(window,text=serviceName,variable=r,value=serviceName,fg='blue',command=threading2).place(x=10,y=align)
                else:
                        if serv_vulns[serviceName]==0:
                                Radiobutton(window,text=serviceName,variable=r,value=serviceName,fg='black',command=threading2).place(x=140,y=align2)
                        else:
                                Radiobutton(window,text=serviceName,variable=r,value=serviceName,fg='blue',command=threading2).place(x=140,y=align2)
                        align2+=40
                
                align=align+40
                radio_count+=1
                
                
                
                pb1['value'] += 5

        
        
        security_headers=["Strict-Transport-Security","Content-Security-Policy","X-Frame-Options","X-XSS-Protection","Referrer-Policy","Cross-Origin-Resource-Policy","HttpOnly","Cache-Control"]
        
        #target=input("Enter the target: ")
        ftp2_3_4=0
        sec_headers=0
        
        '''
        text1.insert(tk.END, "-" * 100)
        text1.insert(tk.END, "\n")
        text1.insert(tk.END, "\n")
        text1.insert(tk.END, "-" * 100)
        text1.insert(tk.END, "\n")
        '''
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # returns an error indicator
        result = s.connect_ex((target,port))
        if result ==0:
                open_ports.append(port)
                serviceName = socket.getservbyport(port, "tcp")
                serv_vulns[serviceName]=0
                selected("0")
                
                
                
                
                
                print("xxxxxxxxxxxxxxxxxxxxxxxxxxxxx: "+serviceName)
                '''
                text1.insert(tk.END, "\n")
                text1.insert(tk.END, "-" * 100)
                text1.insert(tk.END, "\n")
                text1.insert(tk.END, f"\nPort {port} is open Service: {serviceName}",'found')
                '''
                if serviceName=="ftp":
                        data="Give me the version"
                        try:
                                s.send(data.encode())
                                try:
                                        banner=s.recv(1000).decode()
                                        if "2.3.4" in banner:
                                                serv_vulns[serviceName]=1
                                                ftp_vuln=1
                                                ftp2_3_4=1
                                                f=open("ftp/ftp_vulns.txt","w")
                                                f.write("[+] FTP protocol is running on 2.3.4 version. It is vulnerable to command execution!!\nPlease update the version to mitigate.")
                                                f.close()
                                                '''
                                                text1.insert(tk.END, "\n")
                                                text1.insert(tk.END, "[+]",'found')
                                                text1.insert(tk.END, "\n")
                                                text1.insert(tk.END, "FTP protocol on port 21 is vulnerable to command execution!! Please update the version to mitigate.",'warning')
                                                '''
                                except:
                                        print("Data alinamadi")
                        except: 
                                print("Data gonderilemedi")
                if serviceName=="http":
                        missing_headers=[]
                        f=open("http/http_vulns.txt","w")
                        url="http://"+target
                        r2=requests.get(url)
                        http_info="0"
                        if 'Server' in r2.headers:
                                serv_vulns[serviceName]=1
                                http_info=r2.headers['Server']
                                f.write("[+] HTTP Server info: "+http_info+"\n")
                        for header in security_headers:
                                if header not in r2.headers:
                                        serv_vulns[serviceName]=1
                                        sec_headers=1
                                        missing_headers.append(header)
                        if sec_headers==1:
                                
                                f.write("[+] Some security headers are missing in HTTP headers!!\nMissing Headers: ")
                                #f.write(missing_headers)

                                '''
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END, "[+]",'found')
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END, "HTTP Server info"+http_info,'info')
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END, "Some security headers are missing in HTTP headers!!",'warning')
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END, "Missing Headers:",'warning')
                                text1.insert(tk.END, "\n")
                                
                        '''
                        for i in missing_headers:
                                f.write(i+",")
                                #text1.insert(tk.END, i+", ",'warning')
                        
                        output3=open("http/output.txt","w")
                        command="python3 http/okadminfinder3/okadminfinder.py -u "+target+" -r > http/output.txt"
                        
                        os.system(command)
                        admin_panel=0
                        output3.close()
                        output3=open("http/output.txt")
                        sonuc=output3.readlines()
                        for i in sonuc:
                                if "found!" in i:
                                        if admin_panel==0:
                                                f.write("\n[+] Admin panel found in the website!!\n")
                                                admin_panel=1
                                        f.write(i)
                                        '''
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, i,'info')
                                        '''
                        f.close()
                if serviceName=="https":
                        missing_headers=[]
                        f=open("https/https_vulns.txt","w")
                        url="https://"+target
                        r2=requests.get(url)
                        https_info="0"
                        if 'Server' in r2.headers:
                                serv_vulns[serviceName]=1
                                https_info=r2.headers['Server']
                                f.write("[+] HTTPS Server info: "+https_info)
                        for header in security_headers:
                                if header not in r2.headers:
                                        serv_vulns[serviceName]=1
                                        sec_headers=1
                                        missing_headers.append(header)
                        if sec_headers==1:
                                
                                f.write("[+] Some security headers are missing in HTTP headers!!\nMissing Headers:")
                                #f.write(missing_headers)

                                '''
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END, "[+]",'found')
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END, "HTTP Server info"+http_info,'info')
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END, "Some security headers are missing in HTTP headers!!",'warning')
                                text1.insert(tk.END, "\n")
                                text1.insert(tk.END, "Missing Headers:",'warning')
                                text1.insert(tk.END, "\n")
                                
                        '''
                        for i in missing_headers:
                                f.write(i)
                                #text1.insert(tk.END, i+", ",'warning')
                        
                        output3=open("https/output.txt","w")
                        command="python3 http/okadminfinder3/okadminfinder.py -u "+target+" -r > https/output.txt"
                        
                        os.system(command)
                        admin_panel=0
                        output3.close()
                        output3=open("https/output.txt")
                        sonuc=output3.readlines()
                        for i in sonuc:
                                if "found!" in i:
                                        if admin_panel==0:
                                                f.write("[+] Admin panel found in the website!!")
                                                admin_panel=1
                                        f.write(i)
                                        '''
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, i,'info')
                                        '''
                        f.close()        
                
                if serviceName=="ssh":
                        
                        '''
                        text1.insert(tk.END, "\n")
                        text1.insert(tk.END, "Trying to connect to SSH with default username and password lists...")
                        '''
                        host = target
                        users_pass=open("ssh/default_ssh_user_pass.txt")
                        is_ssh_open(target)

                
                if serviceName=="telnet":
                        f3=open("logs.txt","a")
                        f3.write("\nTrying to connect to telnet with default credentials...\n")
                        f3.write("-"*50)
                        f3.close()
                        
                        '''
                        text1.insert(tk.END, "\n")
                        text1.insert(tk.END, "Trying to connect to telnet with default username and password lists...")
                        '''
                        output=open("telnet/output.txt","w")
                        command="hydra "+"telnet://"+target+" -C "+ "telnet/default_creds.txt "+" -t 40 > telnet/output.txt"
                        
                        os.system(command)
                        
                        output.close()
                        output=open("telnet/output.txt")
                        sonuc=output.readlines()
                        telnet_vuln=0
                        f=open("telnet/telnet_vulns.txt","w")
                        for i in sonuc:
                                if "login" and "password" in i:
                                        serv_vulns[serviceName]=1
                                        if telnet_vuln==0:
                                                f.write("[+]")
                                                f.write("Telnet protocol is using default credentials!!\n\n")
                                                '''
                                                text1.insert(tk.END, "\n")
                                                text1.insert(tk.END, "[+]",'found')
                                                text1.insert(tk.END, "\n")
                                                text1.insert(tk.END, "Telnet protocol is using default credentials!!",'warning')
                                                '''
                                                telnet_vuln=1
                                        f.write(i)
                                        telnet_vuln=1
                                        '''
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, i,'warning')
                                        '''
                        f.close()               
                        output.close()                  
                if serviceName=="smtp":
                        f=open("smtp/smtp_vulns.txt","w")
                        f2=open("smtp/smtp_output.txt","w")
                        command="smtp-user-enum -M VRFY -U smtp/top-usernames-shortlist.txt -t "+target+" > smtp/smtp_output.txt"
                        os.system(command)
                        f2.close()
                        f2=open("smtp/smtp_output.txt")
                        smtp_vuln=0
                        for i in f2.readlines():
                                
                                        
                                if "exists" in i:
                                        if smtp_vuln==0:
                                                f.write("[+] Information disclosure vulnerability detected on SMTP!!\nUsers that detected on SMTP service:\n")
                                                smtp_vuln=1
                                        serv_vulns[serviceName]=1
                                        f.write(i)
                                        '''
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, i,'warning')
                                        '''
                        f.close()
                global first
                if serviceName=="netbios-ssn" and first==0:
                        f=open("smb/smb_vulns.txt","w")
                        f2=open("smb/smb_output.txt","w")
                        command="nmap -sV -p 139 "+target+" > smb/smb_output.txt"
                        os.system(command)
                        f2.close()
                        f2=open("smb/smb_output.txt")
                        output2=f2.readlines()
                        first+=1
                        f3=open("logs.txt","a")
                        f3.write("\nGetting version of samba protocol...\n")
                        f3.write("-"*50)
                        f3.close()
                        
                        for i in output2:
                                if "smbd 3.X" in i:
                                        serv_vulns[serviceName]=1
                                        f.write("[+] Samba protocol 3.X version is detecteded.\nIt is vulnerable to arbitrary code execution!!\n")
                                        f.write("Reference: https://nvd.nist.gov/vuln/detail/CVE-2007-2447")
                                        '''
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, "[+]",'found')
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, "Samba protocol 3.X is detecteded. It is vulnerable to arbitrary code execution!!",'warning')
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, "Reference: https://nvd.nist.gov/vuln/detail/CVE-2007-2447",'warning')
                                        '''
                        f.close()
                if serviceName=="mysql":
                        f=open("mysql/mysql_vulns.txt","w")
                        f3=open("logs.txt","a")
                        f3.write("\nTrying to connect to mysql with default credentials...\n")
                        f3.write("-"*50)
                        f3.close()
                        '''
                        text1.insert(tk.END, "\n")
                        text1.insert(tk.END, "Trying to connect to mysql with default username and password lists...")
                        '''
                        f2=open("mysql/mysql_output.txt","w")
                        command="python3 mysql/mysql_bruteforce.py -H "+target+" -U mysql/usernames.txt -p mysql/pass.txt -P "+str(port)+" > mysql/mysql_output.txt"
                        os.system(command)
                        f2.close()
                        f2=open("mysql/mysql_output.txt")
                        output2=f2.readlines()
                        for i in output2:
                                if "Login success!" in i:
                                        serv_vulns[serviceName]=1
                                        f.write("[+] MySQL protocol is using default credentials!!")
                                        i=i.replace("[0;m","")
                                        f.write(i.split("[+]")[1])
                                        '''
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, "[+]",'found')
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, "MySQL protocol is using default credentials!!",'warning')
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, i.split("[+]")[1],'warning')        
                                        '''
                                        break
                        f.close()
                        f2.close()
                if serviceName=="postgresql":
                        

                        
                        #text1.insert(tk.END, "\n\nTrying to connect postgresql with default credentials...")
                        f3=open("logs.txt","a")
                        f3.write("\nTrying to connect postgresql with default credentials...\n")
                        f3.write("-"*50)
                        f3.close()
                        #print("\nTrying to connect postgresql with default credentials...")
                        f2=open("postgres/postgres_output.txt","w")
                        command="hydra -C postgres/creds.txt "+target+" postgres > postgres/postgres_output.txt"
                        os.system(command)
                        f2.close()
                        f2=open("postgres/postgres_output.txt")
                        output2=f2.readlines()
                        for i in output2:
                                if "login:" in i:
                                        f=open("postgres/postgres_vulns.txt","w")
                                        serv_vulns[serviceName]=1
                                        f.write("[+] PostgreSQL service is using default credentials!!\n")
                                        f.write(i)
                                        '''
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, "[+]",'found')
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, "PostgreSQL service is using default credentials!!",'warning')
                                        text1.insert(tk.END, "\n")
                                        text1.insert(tk.END, i,'warning')
                                        text1.insert(tk.END, "\n")
                                        '''
                                        #print(colored("PostgreSQL service is using default credentials!!","red"))
                                        ##print(colored(i,"green"))
                                        break
                        f.close()
                        f2.close()
                if serviceName=="nfs":
                        f3=open("logs.txt","a")
                        f3.write("\nTrying to find mountable directories on NFS share...\n")
                        f3.write("-"*50)
                        f3.close()
                        
                        f2=open("nfs/nfs_output.txt","w")
                        command="showmount -e "+target+" > nfs/nfs_output.txt"
                        os.system(command)
                        f2.close()
                        f2=open("nfs/nfs_output.txt")

                        output2=f2.readlines()
                        if len(output2)>1:
                                serv_vulns[serviceName]=1
                                f=open("nfs/nfs_vulns.txt","w")
                                f.write("Mountable directories on NFS:\n"+output2[1])
                        f.close()        
                        f2.close()
                if "exec" and "login" and "shell" in serv_vulns.keys():
                        f3=open("logs.txt","a")
                        f3.write("\nR services are detected! Trying to remote access to the target as root...\n")
                        f3.write("-"*50)
                        f3.close()
                        serv_vulns["shell"]=1
                        f=open("remote_access/exec_vulns.txt","w")
                        f.write("R services is detected on the machine!!\n512,513 and 514 port are open.\nUse rlogin command line tool to access the machine.")
                        f.close()
                                
                        
                
                        
                if serviceName!="rmiregistry":
                        if radio_count < 15:
                                if serv_vulns[serviceName]==0:
                                        Radiobutton(window,text=serviceName,variable=r,value=serviceName,fg='black',command=threading2).place(x=10,y=align)
                                else:
                                        Radiobutton(window,text=serviceName,variable=r,value=serviceName,fg='blue',command=threading2).place(x=10,y=align)
                        else:
                                if serv_vulns[serviceName]==0:
                                        Radiobutton(window,text=serviceName,variable=r,value=serviceName,fg='black',command=threading2).place(x=140,y=align2)
                                else:
                                        Radiobutton(window,text=serviceName,variable=r,value=serviceName,fg='blue',command=threading2).place(x=140,y=align2)
                                align2+=40
                        align=align+40
                        radio_count+=1
                
                
                
                
                pb1['value'] += 5
        s.close()

global r
r=StringVar()
r.set("0")
global align
global align2
align=300
align2=300
def clicked():
        ip.config(state=DISABLED)
        port1.config(state=DISABLED)
        btn.config(state=DISABLED)
        print(port1.get())
        target=""
        target=ip.get()
        
        start_label=Label(window,text="Scanning Target: " + target,fg="red")
        start_label.place(x=10,y=180)
        timee=str(datetime.now())
        start_label2=Label(window,text="Scanning started at: "+timee,fg="red")
        start_label2.place(x=10,y=210)
        start_label3=Label(window,text="Open port will be shown below.",fg="red")
        start_label3.place(x=10,y=240)
        start=Label(window,text="Blue",fg="blue")
        start.place(x=10,y=270)
        start_label4=Label(window,text="colour means vulnerability found in related protocol.",fg="red")
        start_label4.place(x=43,y=270)
        global r
        Radiobutton(window,text="Logs",variable=r,value="0",fg='black',command=threading2).place(x=420,y=270)
        
        ports=port1.get()
        if (len(ports.split("-"))==2):
                port_1=int(ports.split("-")[0])
                port_2=int(ports.split("-")[1])
                portRange=1
        else:
                portRange=0
                one_port=int(port1.get())
        
        
        if (ip_or_hostname(target))=="False":
                try:
                        target=socket.gethostbyname(target)
                except:
                        print("Hostname is not valid!")
        

        try:
                # will scan ports between 1 to 65,535
                if portRange==1:
                        for port in range(port_1,port_2):
                                
                                scan_port(target, port)
                                
                else:
                        
                        scan_port(target, one_port)
        except KeyboardInterrupt:
                print("\n Exiting Program !!!!")
                sys.exit()
        except socket.gaierror:
                print("\n Hostname Could Not Be Resolved !!!!")
                sys.exit()
        except socket.error:
                print("\ Server not responding !!!!")
                pass

        pb1['value'] =100
        selected("0")
        '''
        if ftp2_3_4==1:
                text1.insert(tk.END, "\n")
                text1.insert(tk.END, "[+]",'found')
                text1.insert(tk.END, "\n")
                text1.insert(tk.END, "Do you want to exploit FTP backdoor vulnerability? (y/n):",'found')
                print("Do you want to exploit FTP backdoor vulnerability? (y/n):")
                time.sleep(10)
                if choice.get()=="y":
                        exploit = subprocess.run(["python3","ftp/ftp_exploit.py",target])
                        text1.insert(tk.END, "\n")
                        text1.insert(tk.END, exploit,'found')
        '''
def threading1():
        t1=Thread(target=clicked)
        t1.start()
def threading2():
        t2=Thread(target=selected(r.get()))
        t2.start()
def threading3(command):
        t3=Thread(target=os.system(command))
        t3.start()

btn = Button(window, text="Scan!",command=threading1)

btn.place(x=400,y=125)

prog=Label(window,text="Progress:",fg="blue")
prog.place(x=500,y=100)

pb1 = Progressbar(window, orient=HORIZONTAL, length=200, mode='determinate')
pb1.place(x=500,y=125)
window.mainloop()