import doctest

def ip_lte(a, b):
    """Return True if ip address `a` is less than or equal to ip address `b`."""
    a = [int(x) for x in a.split('.')]
    b = [int(x) for x in b.split('.')]
    for l, u in zip(a, b):
        if l > u:
            return False
    return True

def ip_gte(a, b):
    """Return True if ip address `a` is greater than or equal to ip address `b`."""
    a = [int(x) for x in a.split('.')]
    b = [int(x) for x in b.split('.')]
    for l, u in zip(a, b):
        if l < u:
            return False
    return True

def min_ip(*args):
    minimum = args[0]
    for y in args[1:]:
        if ip_lte(y, minimum):
            minimum = y
    return minimum

def max_ip(*args):
    maximum = args[0]
    for y in args[1:]:
        if ip_gte(y, maximum):
            maximum = y
    return maximum

class Policy:
    def __init__(self, port_range, ip_range):
        """
        Container for policy rules.

        Parameters
        ----------
        port_range : str
            'min_port-max_port' or 'port' is the range of possible values
            for port numbers. The range is inclusive.
        ip_range : str
            'min_ip-max_ip' or 'ip' is the range of possible ip addresses.
            The range is inclusive.

        Properties
        ----------
        self.min_port, self.max_port : int
            The lower and upper bounds for port ranges for the given `Policy`.
            
        self.min_ip, self.max_ip : str
            The lower and upper bounds for ip addresses for the given `Policy`.
        """
        self.port_range = port_range
        self.ip_range = ip_range

        if '-' in port_range:
            self.min_port, self.max_port = port_range.split('-')
        else:
            self.min_port = self.max_port = port_range
        self.min_port = int(self.min_port)
        self.max_port = int(self.max_port)
        
        if '-' in ip_range:
            self.min_ip, self.max_ip = ip_range.split('-')
        else:
            self.min_ip = self.max_ip = ip_range

    def contains(self, port, ip_address):
        """Return True if `port` and `ip_address` are in the valid ranges."""
        return self.min_port <= port <= self.max_port and ip_lte(self.min_ip, ip_address)\
                and ip_lte(ip_address, self.max_ip)

    def __eq__(self, other):
        return self.min_port == other.min_port and self.max_port == other.max_port\
               and self.min_ip == other.min_ip and self.max_ip == other.max_ip

    def __hash__(self):
        return hash((self.min_ip, self.max_ip, self.min_port, self.max_port))

    def __repr__(self):
        return 'Policy' + repr((self.port_range, self.ip_range))

class PolicyGroup:
    """Data structure for containing `Policy` objects and handling queries
    about whether a (range, ip_address) combination is allowed by any of
    the policies."""
    def __init__(self):
        self.policies = set()
        self.min_port = 65535
        self.max_port = 1
        # If you can't understand what these two lines do, I don't want to work
        # for you :)
        self.min_ip = '255.255.255.255'
        self.max_ip = '0.0.0.0'

    def __iter__(self):
        for x in self.policies:
            yield x

    def contains(self, port, ip_address):
        """Return True if `port` and `ip_address` match any of the policies."""
        if not(self.min_port <= port <= self.max_port and ip_lte(self.min_ip, ip_address)
                and ip_lte(ip_address, self.max_ip)):
            return False  # if the packet is outside the range of any of our policies
        for policy in self.policies:
            if policy.contains(port, ip_address):
                return True
        return False

    def add(self, policy):
        # set the global minimum and maximum ports and ip addresses
        # for the policy group
        self.min_port = min(self.min_port, policy.min_port)
        self.max_port = max(self.max_port, policy.max_port)
        self.min_ip = min_ip(self.min_ip, policy.min_ip)
        self.max_ip = max_ip(self.max_ip, policy.max_ip)
        self.policies.add(policy)

class Firewall:
    def __init__(self, csv_path):
        self.policy_groups = {('inbound', 'tcp'): PolicyGroup(), ('outbound', 'tcp'): PolicyGroup(),
                              ('inbound', 'udp'): PolicyGroup(), ('outbound', 'udp'): PolicyGroup()}

        # add each policy to the corresponding `PolicyGroup`
        with open(csv_path, 'r') as f:
            for line in f:
                direction, protocol, port_range, ip_range = line.strip().split(',')
                policy_group = self.policy_groups[(direction, protocol)]
                policy_group.add(Policy(port_range, ip_range))

    def accept_packet(self, direction, protocol, port, ip_address):
        """
        Return True if there is a rule that allows the given packet.
        
        Parameters
        ----------
        direction : str
            Packet direction: one of 'inbound' or 'outbound'.
        protocol : str
            Internet protocol: one of 'tcp' or 'udp'.
        port : int
            Port number in the range [1, 65535].
        ip_address : str
            IPv4 address, assumed to be well formed.

        Returns
        -------
        bool
            True if the packet is allowed by the firewall policy. False otherwise.
        """
        policy_group = self.policy_groups[(direction, protocol)]
        if policy_group.contains(port, ip_address):
            return True
        return False

if __name__ == "__main__":
    doctest.testmod()
