import random


def TCP_Distribution(time, lamda):
    x = random.randint(0, 100)
    if x <= 15:
        return time / random.randint(1, 10000*lamda), 0
    elif x <= 20:
        return time / random.randint(10000*lamda, 20000*lamda), 0
    elif x <= 30:
        return time / random.randint(20000*lamda, 30000*lamda), 0
    elif x <= 40:
        return time / random.randint(30000*lamda, 40000*lamda), 0
    elif x <= 53:
        return time / random.randint(40000*lamda, 50000*lamda), 0
    elif x <= 60:
        return time / random.randint(80000*lamda, 200000*lamda), 0
    elif x <= 70:
        return time / random.randint(100000*lamda, 1000000*lamda), 0
    elif x <= 80:
        return time / random.randint(120000*lamda, 1400000*lamda), 0
    elif x <= 90:
        return time / random.randint(140000*lamda, 1800000*lamda), 1
    elif x <= 97:
        return time / random.randint(180000*lamda, 2000000*lamda), 1
    else:
        return time / random.randint(2000000*lamda, 3000000*lamda), 1
