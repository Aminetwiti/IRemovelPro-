import os, shutil
p = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\06_LOCAL_REPRODUCER\iact_reproducer\mock_server.py"
if os.path.exists(p):
    dest = p + ".corrupted"
    if os.path.exists(dest):
        os.remove(dest)
    shutil.move(p, dest)
    print("MOVED to:", dest)
else:
    print("NOT FOUND")