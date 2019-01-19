#!/usr/bin/env python3
import os
import random
import shutil
import unittest

import firewall

# NOTE: This script creates and deletes a directory named '__tmp__'.
# (without the single quotation marks). Please do not run this script
# in a folder that contains a directory with that name because it will
# raise an error.

def random_ip(lower='0.0.0.0'):
    digits = []
    lower_bounds = [int(x) for x in lower.split('.')]
    for i in range(4):
        digits.append(random.randint(lower_bounds[i], 255))
    return '.'.join(map(str, digits))

def random_query():
    direction = random.choice(('inbound', 'outbound'))
    protocol = random.choice(('tcp', 'udp'))
    port = random.randint(1, 65535)
    return direction, protocol, port, random_ip()

def random_policy():
    direction = random.choice(('inbound', 'outbound'))
    protocol = random.choice(('tcp', 'udp'))

    lower_port = random.randint(1, 65535)
    upper_port = random.randint(lower_port, 65535)
    if lower_port == upper_port:
        port_range = str(lower_port)
    else:
        port_range = str(lower_port) + '-' + str(upper_port)

    lower_ip = random_ip()
    upper_ip = random_ip(lower_ip)
    if lower_ip == upper_ip:
        ip_range = lower_ip
    else:
        ip_range = lower_ip + '-' + upper_ip
    return ','.join((direction, protocol, port_range, ip_range))

class FirewallTest(unittest.TestCase):
    def run_test(self, n):
        fw = firewall.Firewall('test_inputs/%s_policy.csv' % n)
        with open('test_inputs/%s.csv' % n, 'r') as inputs:
            with open('test_outputs/%s.txt' % n, 'r') as outputs:
                for i, (in_line, out_line) in enumerate(zip(inputs, outputs)):
                    direction, protocol, port, ip_address = in_line.strip().split(',')
                    port = int(port)
                    result = fw.accept_packet(direction, protocol, port, ip_address)
                    self.assertEqual(str(result), out_line.strip())

class TestFirewall(FirewallTest):
    def test_00_example(self):
        self.run_test(0)
    def test_01_good(self):
        """Test with ports and ip addresses that are all in range of policies."""
        self.run_test(1)
    def test_02_bad(self):
        """Test with ports and ip addresses that are all out of range of policies."""
        self.run_test(2)

# the next two tests are for the performance of the firewall
# TestBig creates a 'large' size file (1M) with many duplicate policies
class TestBig(unittest.TestCase):
    def test_03_repeats(self):
        duplicates = ['inbound,tcp,80-85,192.168.1.1', 'outbound,udp,500-600,1.1.1.1',
                      'outbound,tcp,323,5.4.3.2-5.4.4.5', 'inbound,udp,842,9.2.3.5']
        os.mkdir('__tmp__')
        random.seed(0)
        with open('__tmp__/big.csv', 'w') as f:
            for i in range(1000000):
                f.write(random.choice(duplicates) + '\n')
        fw = firewall.Firewall('__tmp__/big.csv')
        # make 1000 random queries
        for i in range(1000):
            fw.accept_packet(*random_query())
        shutil.rmtree('__tmp__')

# TestRandom creates a 'medium' size file (0.5M) with many random policies
class TestRandom(unittest.TestCase):
    def test_04_random(self):
        os.mkdir('__tmp__')
        random.seed(0)
        with open('__tmp__/random.csv', 'w') as f:
            for i in range(500000):
                f.write(random_policy() + '\n')
        fw = firewall.Firewall('__tmp__/random.csv')
        # make 1000 random queries
        for i in range(1000):
            fw.accept_packet(*random_query())
        shutil.rmtree('__tmp__')

if __name__ == "__main__":
    res = unittest.main(verbosity=3, exit=False)
