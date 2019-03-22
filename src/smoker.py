from multiprocessing import Process
import random
import time
import sysv_ipc

items = ["paper", "tobacco", 'matches']


def smoker(worker_queue, merchant_queue, type):
    while True:
        item, _ = worker_queue.receive(type=items.index(type) + 1)
        print(f"    Smoker with {type}: received {item.decode('utf-8')}")
        time.sleep(1)
        merchant_queue.send(message=f"Smoker with {type}: smoked", type=4)


workers = []


def main():
    global workers
    worker_queue = sysv_ipc.MessageQueue(None, sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL)
    merchant_queue = sysv_ipc.MessageQueue(None, sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL)
    print("Starting...")
    workers = [Process(target=smoker, args=(worker_queue, merchant_queue, item)) for item in items]
    for w in workers:
        w.start()

    while True:
        smp = random.sample(items, len(items) - 1)
        type = [i for i, x in enumerate(items) if x not in smp][0] + 1
        print(f'Merchant sells {smp}')
        worker_queue.send(message=str(smp), type=type)
        print('    ' + merchant_queue.receive(type=4)[0].decode('utf-8'))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        for w in workers:
            w.join()
        print("Out")
