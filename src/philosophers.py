from multiprocessing import Process, Pipe
import queue
import time
import random
import enum

philosopher_number = 5


class MessageType(enum.Enum):
    request = 'request'
    response = 'response'
    exit = 'exit'


class Message:
    def __init__(self, id, clock, type):
        self.id = id
        self.clock = clock
        self.type = type

    def __str__(self):
        return f"{self.id}:{self.clock}:{self.type.value}"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self.clock == other.clock


def message_from_string(string):
    split = string.split(':')
    return Message(int(split[0]), int(split[1]), MessageType(split[2]))


class Philosopher(Process):
    def __init__(self, id):
        super(Philosopher, self).__init__()
        self.id = id
        self.left_fork = False
        self.right_fork = False
        self.q = queue.PriorityQueue()
        self.in_pipes = {}
        self.out_pipes = {}
        self.clock = 3 * (id + 1)
        print(f"Init philosopher {self.id}")

    def add_in_pipe(self, sender, pipe):
        self.in_pipes[sender] = pipe

    def add_out_pipe(self, reciever, pipe):
        self.out_pipes[reciever] = pipe

    def send_requests(self, request):
        for p in self.out_pipes:
            self.out_pipes[p].send(str(request))

    def add_request(self, request):
        self.q.put((request.clock, request))

    def run(self):
        print(f"Started philosopher {self.id}")
        responses = 0
        wait = False

        init_time = self.clock

        while True:
            time.sleep(2)
            if not wait and random.choice([True, False]):
                print(f"Philosopher {self.id} wants to eat")
                request = Message(self.id, self.clock, MessageType.request)
                init_time = self.clock
                self.send_requests(str(request))
                wait = True
                self.add_request(request)
                responses = 0

            for p in self.in_pipes:
                pipe = self.in_pipes[p]
                if pipe.poll():
                    recv = message_from_string(pipe.recv())
                    self.clock = max(self.clock, recv.clock) + 1

                    if recv.type == MessageType.request:
                        self.add_request(recv)
                        self.out_pipes[recv.id].send(str(Message(self.id, self.clock, MessageType.response)))
                    elif recv.type == MessageType.response:
                        responses += 1
                        print(f"Philosopher {self.id} received a response from {recv.id}")
                    elif recv.type == MessageType.exit:
                        # TODO
                        tmp = self.q.get()[1]
                        if tmp.id != recv.id and tmp.clock != recv.clock:
                            print('Error removing from queue')
                        print(f"Philosopher {self.id} removed a message from {recv.id}")
                        if wait:
                            # TODO
                            pass

            if self.q.empty():
                continue

            tmp = self.q.get()[1]
            if tmp.id == self.id and responses >= (philosopher_number - 1):
                print(f"Philosopher {self.id} sits")
                time.sleep(2)
                responses = 0
                wait = False
                print(f"Philosopher {self.id} leaves")
                self.send_requests(Message(self.id, init_time, MessageType.exit))
            else:
                self.add_request(tmp)





def main():
    philosophers = [Philosopher(i) for i in range(philosopher_number)]

    for p in philosophers:
        for x in philosophers:
            if x is p:
                continue
            a, b = Pipe(False)  # disable duplex comm
            p.add_out_pipe(x.id, b)
            x.add_in_pipe(p.id, a)

    for p in philosophers:
        p.start()
    # while True:
    #     pass


if __name__ == '__main__':
    main()