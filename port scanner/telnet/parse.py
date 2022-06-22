f=open("default_creds.txt")
w1=open("usernames.txt","w")
w2=open("passwords.txt","w")
for i in f.readlines():
    username=i.split(":")[0]
    password=i.split(":")[1]
    w1.write(username)
    w1.write("\n")
    w2.write(password)
