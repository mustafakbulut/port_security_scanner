from tkinter import *  
from tkinter import ttk
import tkinter
import os
import time
from datetime import datetime
from tkinter.ttk import Progressbar
window = Tk()

window.title("Port Security Scanner") 
window.geometry("1000x1000")  

labelframe1 = LabelFrame(window, text="Scan Settings",height=200,width=400)  
labelframe1.place(x=20,y=30)

labelframe2=LabelFrame(window,text="Output",height=600,width=960)
labelframe2.place(x=20,y=250)

lblip = Label(window, text="Host:")
lblip.place(x=50,y=70)

ip = Entry(window,width=13)
ip.place(x=100,y=70)

lbl2=Label(window,text="Port or Port Range (21, 0-1000):")
lbl2.place(x=50,y=110)

port1=Entry(window,width=10)
port1.place(x=270,y=110)


vuln = Label(window, text="Vulnerabilities:",font='Helvetica 13 bold')
vuln.place(x=500,y=300)


text1=tkinter.Text(window, height=25, width=55)

text1.place(x=500,y=320)

btn = Button(window, text="\u25B6"+" Scan!")
text1.insert(tkinter.END, "\n")
text1.insert(tkinter.END, "[+] FTP protocol is running on 2.3.4 version.\nIt is vulnerable to command execution!! Please update the version to mitigate.")
btn.place(x=50,y=150)

prog=Label(window,text="Progress:",fg="blue")
prog.place(x=500,y=90)

pb1 = Progressbar(window, orient=HORIZONTAL, length=200, mode='determinate')
pb1.place(x=500,y=120)


start_label=Label(window,text="Scanning Target: 192.168.1.122" ,fg="red")
start_label.place(x=500,y=35)
timee=str(datetime.now())
start_label2=Label(window,text="Scanning started at: "+timee,fg="red")
start_label2.place(x=500,y=60)

tabl = ttk.Treeview(window,height=25)
tabl['columns'] = ('port', 'service', 'vuln')
tabl.column("#0", width=0,  stretch=NO)
tabl.column("port",anchor=CENTER, width=80)
tabl.column("service",anchor=CENTER,width=140)
tabl.column("vuln",anchor=CENTER,width=170)

tabl.heading("#0",text="",anchor=CENTER)
tabl.heading("port",text="Port",anchor=CENTER)
tabl.heading("service",text="Service",anchor=CENTER)
tabl.heading("vuln",text="Vulnerability Status",anchor=CENTER)


tabl.insert(parent='',index='end',iid=0,text='x',
values=('21','ftp','\u2713'))
tabl.insert(parent='',index='end',iid=1,text='',
values=('22','ssh',u'\u2713'))

def selectItem(a):
    curItem = tabl.focus()
    print(tabl.item(curItem)['values'][1])
tabl.bind('<Button-1>', selectItem)




















tabl.place(x=50,y=300)





window.mainloop()  