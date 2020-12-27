import time
import random
import set3_challenge21 as mt


def get_random_number():
    time.sleep(random.randint(4, 1000))
    seed = int(time.time())
    rng = mt.MT19937(seed)
    time.sleep(random.randint(4, 1000))
    return {'rand': rng.extract_number(), 'seed': seed}


def crack_seed(random_number):
    curr_time = int(time.time())
    for seed in range(curr_time - 1000, curr_time):
        if mt.MT19937(seed).extract_number() == random_number:
            return seed


if __name__ == "__main__":
    r = get_random_number()
    seed = crack_seed(r['rand'])
    print(seed)
    assert(seed == r['seed'])