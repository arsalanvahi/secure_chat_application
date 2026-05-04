import threading
import time

def task(name):
    for i in range(3):
        print(name, i)
        time.sleep(1)

t1 = threading.Thread(target=task, args=("A",))
t2 = threading.Thread(target=task, args=("B",))

t1.start()
t2.start()

t1.join()
t2.join()