import os

with open("src/lib.rs", "r") as f:
    lib_rs = f.read()

# I will write the python script to replace lib.rs contents entirely, as it's cleaner.
