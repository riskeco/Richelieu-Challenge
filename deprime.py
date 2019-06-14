
import itertools
import re


def read_prime():

    hdata = ''

    with open('prime.txt', 'r') as fd:
        data = fd.read()

    for line in data.split('\n'):

        if not(line.startswith('    ')):
            continue

        line = line.lstrip('    ')

        hdata += line

    return hdata


def replace(data, ops):

    old, new = ops[0]

    count = data.count(new)

    # product('ABCD', repeat=2)
    # AA AB AC AD BA BB BC BD CA CB CC CD DA DB DC DD

    combinations = list(itertools.product([old, new], repeat=count))

    positions = [ m.start() for m in re.finditer(new, data) ]

    for c in combinations:

        new_data = data

        for i in range(count):

            new_data = new_data[:positions[i]] + c[i] + new_data[positions[i] + 2:]

        assert(len(data) == len(new_data))

        if len(ops) == 1:

            global counter

            with open('OUTPUT-%u' % counter, 'w') as fd:
                fd.write(new_data)

            counter += 1

        else:

            replace(new_data, ops[1:])


sed_ops = [
    [ '7f', 'fb' ],
    [ 'e1', '66' ],
    [ 'f4', '12' ],
    [ '16', '54' ],
    [ 'a4', '57' ],
    [ 'b5', 'cd' ],
]

sed_ops.reverse()

data = read_prime()

counter = 0

replace(data, sed_ops)
