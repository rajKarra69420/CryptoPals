# used pseudocode from here: https://en.wikipedia.org/wiki/Mersenne_Twister#Algorithmic_detail
#need to get 32 bit numbers somehow
import numpy as np

class MT19937:
    def __init__(self, seed=5489):
        self.seed = seed
        self.w = 32
        self.n = 624
        self.m = 397
        self.r = 31
        self.a = 0x9908B0DF
        self.u = 11
        self.d = 0xFFFFFFFF
        self.s = 7
        self.b = 0x9D2C5680
        self.t = 15
        self.c = 0xEFC60000
        self.l = 18
        self.f = 1812433253
        self.upper_mask = ((1 << self.w) - 1) - ((1 << self.r) - 1)
        self.lower_mask = (1 << self.r)-1
        self.state = [0] * self.n
        self.index = self.n
        self.initialize_state()

    def initialize_state(self):
        self.state[0] = self.seed
        for i in range(1, self.n):
            self.state[i] = np.uint32(self.f * (self.state[i - 1] ^ (self.state[i - 1] >> (self.w - 2))) + i)

    def temper(self):
        y = self.state[self.index]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index += 1
        return np.uint32(y)

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
        return self.temper()

    def twist(self):
        for i in range(self.n):
            x = np.uint32((self.state[i] & self.upper_mask) + (self.state[(i + 1) % self.n] & self.lower_mask))
            xa = x >> 1
            if x % 2 != 0:
                xa = xa ^ self.a
            self.state[i] = self.state[(i + self.m) % self.n] ^ xa
            self.index = 0
