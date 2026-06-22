"""Clear Python bytecode cache to force module reload."""
import shutil, os
root = r"C:\Users\amine\Downloads\[Bypassfrpfiles.com]iRemoval PRO Premium Edition 5.2\06_LOCAL_REPRODUCER\iact_reproducer\__pycache__"
if os.path.exists(root):
    shutil.rmtree(root)
    print("CLEARED:", root)
else:
    print("NOT FOUND")
