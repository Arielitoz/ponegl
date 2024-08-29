import os

def remove_empyt_file(name):
    if os.path.isfile(name) and os.path.getsize(name) == 0:
        os.remove(name)