from multiprocessing import Process
import random
import time
import sysv_ipc

items = ["paper", "tobacco", 'matches']


def smoker(worker_queue, merchant_queue, type):
    while True:
        type_index = items.index(type) + 1
        item, _ = worker_queue.receive(type=type_index)
        # print(f"    Smoker with {type}: offered {item.decode('utf-8')}")
        merchant_queue.send(message=str(type_index), type=4)
        msg, recv_index = worker_queue.receive(type=type_index)
        print(f"    Merchant sells to smoker with {items[recv_index - 1]}")
        time.sleep(1)
        merchant_queue.send(message=str(type_index), type=4)


def main():
    worker_queue = sysv_ipc.MessageQueue(None, sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL)
    merchant_queue = sysv_ipc.MessageQueue(None, sysv_ipc.IPC_CREAT | sysv_ipc.IPC_EXCL)
    print("Starting...")
    workers = [Process(target=smoker, args=(worker_queue, merchant_queue, item)) for item in items]
    for w in workers:
        w.start()

    while True:
        smp = random.sample(items, len(items) - 1)
        type = [i for i, x in enumerate(items) if x not in smp][0] + 1
        print(f'    Merchant sells {smp}')
        worker_queue.send(message=str(smp), type=type)
        msg = merchant_queue.receive(type=4)[0].decode('utf-8')
        print(f"    Smoker with {items[int(msg) - 1]}: request")
        smoker_type = int(msg[-1])
        worker_queue.send(message="", type=smoker_type)
        recv_type = int(merchant_queue.receive(type=4)[0].decode('utf-8'))
        print(f"    Smoker with {items[recv_type - 1]}: 🚬")

    # for w in workers:
    #     w.join()


if __name__ == "__main__":
    main()
