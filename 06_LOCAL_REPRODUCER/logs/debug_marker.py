import sys
sys.path.insert(0, "06_LOCAL_REPRODUCER")
import iact_reproducer.blacklist as bl_mod
print("Module file:", bl_mod.__file__)
print("TEST_MARKER:", repr(bl_mod.TEST_MARKER))
print("_SEED_UDIDS:", bl_mod._SEED_UDIDS)
print("_SEED_SERIALS:", bl_mod._SEED_SERIALS)
