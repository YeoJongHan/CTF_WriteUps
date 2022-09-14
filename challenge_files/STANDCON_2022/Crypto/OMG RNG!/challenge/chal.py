from Crypto.Util.number import bytes_to_long, getRandomRange

FLAG = bytes_to_long(open("flag.txt", "rb").read())

class MLFG():
    def __init__(self):
        self.m = getRandomRange(2, 2**300)
        self.s0, self.s1 = [getRandomRange(2, self.m-1) for _ in '__']
        self.curr_state = 0
    
    def next(self):
        self.curr_state = (self.s0 * self.s1) % self.m
        self.s0 = self.s1
        self.s1 = self.curr_state
        return self.curr_state


if __name__ == '__main__':
    
    P = MLFG()
    secret = FLAG ^ P.s0 ^ P.s1
    
    [P.next() for _ in range(1337)] # discard some states :p

    for _ in range(5):
        ch = input("\n[1] Get a random gift \n[2] Get Secret! \n\n[?]> ").strip()
        if ch == '1':
            print("\nHere's your gift:", hex(P.next()))
        elif ch == '2':
            print("\nHere's your secret:", hex(secret))
        else:
            exit("\nOops! Invalid input!")
    else:
        exit("\nEnough Gifts!")
