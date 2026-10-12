import os
import sys

# Ensure vendor/rfchunt root is in sys.path for test execution
rfchunt_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if rfchunt_dir not in sys.path:
    sys.path.insert(0, rfchunt_dir)
