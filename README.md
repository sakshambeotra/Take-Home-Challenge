# Program Logic

The program uses a Rules class which consists of a hash map. The hash map uses each value of the corresponding rule as a key (eg. tcp,udp) and returns the line numbers of the rules which have that value. Direction and protocol use this class with no adjustments. I realized that using the class as is for the port number would use to much memory (especially for 500k rules) so instead the hash map takes in the rule line number and returns the corresponding port. The ip address is split into 4 octets and each octet uses a seperate rule class. The hash map returns the rules corresonding to the value of the octet. When the program checks if a packet should be allowed it calls the rules class for the direction,protocol, and ip address. We are left with 6 lists with possible rule values. The program then checks the intersection of these lists to see which rule corresponds to all the inputs (except port). We then check the port values for the rules we are left with and check if any of them match the input port.

# Testing

test.py contains a method to create randomized rules. I used this to populate a csv file with 500000 randomized rules and test them using another method in test.py. The second method creates randomized inputs for the firewall and prints the output and matching set. I ran a few tests and manually confirmed the answers. I also tested for as many edge cases as I could think of. The program can handle large inputs although it takes the firewall object a long time to initialize. However, accept_packet runs extremely fast even with a firewall object with 500k rules. I would definitely liked to have created a more thorough test method if I had more time.

# Instructions

You can run the program by running 'python test.py' in the terminal. test.py creates randomized rules, initializes the firewall, and then runs the program on randomized outputs and prints the results. You can change the number of rules created and tests run by editing the values in the main method of test.py

# Preferences

My first preference would be to work with the data team. 
