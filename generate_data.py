import random

from tqdm import tqdm

_str = ''

for _ in tqdm(range(2**30), total=2**30):
    if random.random() < .5:
        _str += chr(random.randint(65, 90))
    else:
        _str += chr(random.randint(97, 122))

with open('rnd.txt', 'w+') as f:
    f.write(_str)