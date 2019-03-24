from multiprocessing import Process, Pipe, Array
import time
import random
import enum
import os

detail_output = True
long_sleep = True
philosopher_number = 5

# Shared array between processes
chopsticks = Array('b', [False for i in range(philosopher_number)])


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
        return self.clock == other.clock and self.id == other.id and self.type == other.type

    def __lt__(self, other):
        return self.clock < other.clock


# Create a message object from its string representation
def message_from_string(string):
    split = string.split(':')
    return Message(int(split[0]), int(split[1]), MessageType(split[2]))


# Print only if detailed printing is enabled
def dprint(txt):
    if detail_output:
        print(txt)


class Philosopher(Process):
    def __init__(self, id):
        super(Philosopher, self).__init__()
        self.id = id
        self.q = []
        self.chopsticks = False
        self.in_pipes = {}
        self.out_pipes = {}
        self.clock = 3 * (id + 1)
        print(f"Init philosopher {self.id}")

    # Add a receive end of a pipe to a member list
    def add_in_pipe(self, sender, pipe):
        self.in_pipes[sender] = pipe

    # Add a send end of a pipe to a member list
    def add_out_pipe(self, reciever, pipe):
        self.out_pipes[reciever] = pipe

    # Send a message over all output pipes
    def send_messages(self, request):
        for p in self.out_pipes:
            self.out_pipes[p].send(str(request))

    # Add a message to philosopher message queue
    def add_message(self, message):
        self.q.append(message)
        self.q.sort(key=lambda x: x.clock)

    # Test if chopsticks are available and acquire them
    def acquire_chopsticks(self):
        if not chopsticks[self.id - 1] and not chopsticks[self.id]:
            chopsticks[self.id - 1] = True
            chopsticks[self.id] = True
            self.chopsticks = True
            return True
        return False

    # Release chopsticks if in use
    def release_chopsticks(self):
        if not self.chopsticks:
            return False
        chopsticks[self.id - 1] = False
        chopsticks[self.id] = False
        self.chopsticks = False
        return True

    def run(self):
        print(f"Started philosopher {self.id} - {os.getpid()}")
        responses = 0  # number of responses received
        wait = False  # waiting for responses

        init_time = self.clock

        while True:
            time.sleep(1 if long_sleep else 0.1)

            # Request entry to the critical section by sending a request message to other processes
            if not wait and random.choice([True, False]):
                if not self.chopsticks:
                    dprint(f"Philosopher {self.id} wants to eat")  # Request chopsticks
                else:
                    dprint(f"Philosopher {self.id} wants to leave")  # Release chopsticks
                request = Message(self.id, self.clock, MessageType.request)
                init_time = self.clock  # Store the time of initial request to send in an exit message
                wait = True
                self.send_messages(str(request))
                self.add_message(request)
                responses = 0

            # Read messages from input pipes
            for pipe in self.in_pipes.values():
                if pipe.poll():  # See if there is anything to read
                    recv = message_from_string(pipe.recv())
                    self.clock = max(self.clock, recv.clock) + 1  # Update the local logical clock

                    # If the message is a request, store it in a message queue and send a response
                    if recv.type == MessageType.request:
                        self.add_message(recv)
                        self.out_pipes[recv.id].send(str(Message(self.id, self.clock, MessageType.response)))

                    # If the message is a response, count it
                    elif recv.type == MessageType.response:
                        responses += 1
                        dprint(f"Philosopher {self.id} received a response from {recv.id}")

                    # If the message is an exit notification, remove the original request from message queue
                    elif recv.type == MessageType.exit:
                        # aye = None
                        # for i, m in enumerate(self.q):
                        #     if m.id == recv.id and m.type == MessageType.request:
                        #         aye = i
                        # if aye is not None:
                        #     self.q.pop(aye)
                        # else:
                        #     print("Error - request not found")
                        self.q = list(filter(lambda x: x.id != recv.id or x.type != MessageType.request, self.q))
                        dprint(f"Philosopher {self.id} removed a message from {recv.id}")

            if len(self.q) == 0:
                continue

            head = self.q[0]
            if head.id == self.id and responses >= (philosopher_number - 1):
                self.q.pop(0)
                time.sleep(1 if long_sleep else 0.1)
                if not self.chopsticks:
                    if self.acquire_chopsticks():
                        print(f"\033[0;32;0mPhilosopher {self.id} sits\033[0;0;0m")
                else:
                    if self.release_chopsticks():
                        print(f"\033[0;31;0mPhilosopher {self.id} leaves\033[0;0;0m")
                responses = 0
                wait = False
                self.send_messages(Message(self.id, init_time, MessageType.exit))
            elif responses >= (philosopher_number - 1):
                pass
                # print("DEBUG")
                # for e in self.q:
                #     print(f"    Philosopher {self.id} - {str(e)}")


def main():
    philosophers = [Philosopher(i) for i in range(philosopher_number)]

    # Create a pipe between every pair of philosophers
    for p in philosophers:
        for x in philosophers:
            if x is p:
                continue
            a, b = Pipe(False)  # disable duplex comm

            p.add_out_pipe(x.id, b)
            x.add_in_pipe(p.id, a)

    for p in philosophers:
        p.start()


if __name__ == '__main__':
    main()