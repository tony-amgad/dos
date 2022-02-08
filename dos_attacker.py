import os
from joblib import Parallel, delayed

def single_ping(ip_add):
    os.system(f"ping {ip_add}")

number_of_pings=20
ip_add="192.168.1.11"
Parallel(n_jobs=10)(delayed(single_ping) (ip_add,) for i in range(number_of_pings))