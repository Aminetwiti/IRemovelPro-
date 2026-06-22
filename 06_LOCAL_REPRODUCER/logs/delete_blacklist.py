import os
p = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\06_LOCAL_REPRODUCER\logs\blacklist.json"
if os.path.exists(p):
    os.remove(p)
    print("DELETED:", p)
else:
    print("NOT FOUND")
