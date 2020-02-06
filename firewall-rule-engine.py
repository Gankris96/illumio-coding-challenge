import csv
from ipaddress import IPv4Address
import sqlite3
import time
import sys

'''
This Firewall is implemented using an in-memory db object.
My approach was inspired by the fact that this was a classic case of efficient storage and retrieval
and that a database would be the most ideal for such a use-case.
To see if this was possible i looked online for such a concept and i was able to find this post that
helped my idea
https://stackoverflow.com/questions/1038160/data-structure-for-maintaining-tabular-data-in-memory
'''


class Firewall:
    db = None  # The in-memory db object
    current_connection = None  # the db connection object that can be used for performing operations on the db object

    # constructor

    def __init__(self, path_to_csv_rules):
        """
        This is the constructor that takes that path to the csv rules file, performs a pre-processing step and
        builds the db table.
        At the end of this function the FirewallRules table is ready with all the rules specific to the firewall.
        :param path_to_csv_rules:
        """
        # Create an in-memory database
        self.db = sqlite3.connect(':memory:')
        self.current_connection = self.db.cursor()
        self.init_db()
        self.load_rules(path_to_csv_rules)
        return

    # initialize the db and create a table to store the rules
    def init_db(self):
        self.current_connection.execute('''
        CREATE TABLE FirewallRules (
            Direction TEXT,
            Protocol TEXT,
            Port_Start INTEGER ,
            Port_End INTEGER,
            IP_Start TEXT,
            IP_End TEXT)
        ''')

    # insert all the procesed data into the db
    def populate_db(self, data):
        self.current_connection.executemany('''
            INSERT INTO FirewallRules (Direction, Protocol, Port_Start,Port_End, IP_Start, IP_End)
            VALUES (?,?,?,?, ?, ?)''', data)

    # query the db to look for whether the incoming packet can pass through the db
    def query_db(self, query_params, ip_address):
        # check if the db is populated with data

        # check = self.current_connection.execute(
        #     '''SELECT * FROM FirewallRules ''')
        #
        # result object containing the result of the db
        result = self.current_connection.execute(
            '''SELECT IP_Start, IP_End FROM FirewallRules
                    where Direction = ? and Protocol = ? and Port_Start <= ? and Port_End >= ?''',
            query_params)
        # check if any rule is present that matches the required query
        for ip_start, ip_end in result:
            if IPv4Address(ip_start) <= IPv4Address(ip_address) <= IPv4Address(ip_end):
                return True
        return False

    # get the ip-address range
    def get_ip_range(self, ip_range):
        """
        :param ip_range: str containing the ip_range string
        :return: str tuple start_ip, end_ip
        """
        ips = ip_range.strip().split('-')
        if len(ips) == 2:
            start_ip = ips[0]
            end_ip = ips[1]
        else:
            start_ip = end_ip = ips[0]
        return start_ip, end_ip

    def get_port_range(self, port_range):
        """
        :param port_range: port_range str
        :return: int tuple containing the start_port and end_port
        """
        ports = port_range.split('-')
        if len(ports) == 2:
            start_port = ports[0]
            end_port = ports[1]
        else:
            start_port = end_port = ports[0]
        return int(start_port), int(end_port)

    # preprocess the data to load the db with the rules
    def load_rules(self, csv_file):
        rule_set = []
        with open(csv_file, 'r') as rules_csv:
            rules = csv.reader(rules_csv)
            for row in rules:
                direction, protocol, port_range, ip_range = row
                start_port, end_port = self.get_port_range(port_range)
                start_ip, end_ip = self.get_ip_range(ip_range)
                rule_set.append([direction, protocol, start_port, end_port, start_ip, end_ip])
        try:
            self.populate_db(rule_set)
        except sqlite3.Error:
            print("*****Error while loading rules into the DB*****")
            return False

    def accept_packet(self, dirn, protocol, port, ip) -> bool:
        """
        :param dirn: Direction of packet
        :param protocol: protocol
        :param port: desired port number
        :param ip: desired ip
        :returns boolean whether the packet is accepted or not, i.e whether the packet satisfies the configured firewall rules
        """

        # query the db and check if there is a matching rule
        try:
            return self.query_db((dirn, protocol, port, port), ip)
        except sqlite3.Error:
            return False


if __name__ == '__main__':
    start = time.process_time()
    csv_file = "rules.csv"
    if len(sys.argv) == 2:
        csv_file = sys.argv[1]
    fw = Firewall(csv_file)
    print("Rule Engine Loaded in ", time.process_time() - start)

    start = time.process_time()
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
    print("Queried in ", time.process_time() - start)
