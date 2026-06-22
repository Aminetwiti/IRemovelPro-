#!/usr/bin/env python3
"""Wrapper that forces UTF-8 output for tests."""
import sys
import io
import os
# Force UTF-8 for stdout
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Now run the actual test
sys.argv = ['test_standalone.py'] + (sys.argv[1:] if len(sys.argv) > 1 else [])
exec(open('test_standalone.py', encoding='utf-8').read())
