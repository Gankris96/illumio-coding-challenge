# illumio-coding-challenge
My submission for the illumio-coding challenge


# My approach
Since the requirements is to implement a rule-based firewall system, the first thing I thought about when regarding rule-based systems was that rules need to be stored and retrieved quickly. Although I did explore using a dictionary and storing the entire rule set in a kind of hierarchical manner, I felt that doing so involved a lot of complex processing and making sure that the rule set is not violated at any cost was challenging. Hence, I wanted to see if there was a way to use a database in memory. I searched for this idea online and found https://stackoverflow.com/questions/1038160/data-structure-for-maintaining-tabular-data-in-memory to be really what I wanted.
Thus my approach was:
1. Build an in-memory db with the set of rules
2. Query the db with incoming packet specifications
3. Processes the results from the query to see if any rule matches the packet. 

This simplified my implementation and made it really easy to code.


# Testing

I created a separate csv file `my_csv_input_file.csv` which contains certain border cases that I could think of and ran the code with certain queries to test for corner cases. It seemed to work well.

# Performance

I created a csv file with several rules (close to 10000) by using MS Excel to generate some rules. I was able to load the table in under 5 seconds and queries were really performant with results being returned within 1 second for a batch of 50 queries.

# Optimizations and Enhancements 

Although the implementation works well, in this approach I do not make use of the fact that there may be overlapping ranges. Instead I store all rules as is in the db and process all matching query results to decide whether a packet is acceptable. If possible, I would like to enhance the db population to make use of the fact that there are overlaps in terms of port numbers and ip addresses. This would reduce the number of rows in the db, thus saving space and would make the accept packet logic faster as the number of results to be processed from the query would reduce.

With more time, I would have ideally tried to build a tree data-structure that maintains the rules as a tree where the direction of the packet and protocol can serve as root. The port-ranges in sorted order can serve as the second level nodes and the IP - address can serve as the leaf nodes. Thus, tree would represent some sort of a rule-based decision tree. If an incoming packet can be successfully reached during traversal of this tree, then we can `accept` the packet, if not `reject`.

# Execution

## load existing rule set (hard-coded within program)
```
python3 firewall-rule-engine.py
```

## load your own rule set as a csv file 
```
python3 firewall-rule-engine.py <csv_file>
```
