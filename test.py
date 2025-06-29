import pickle
with open('report.dat','rb') as f:
    s = pickle.load(f)
    print(s)
    