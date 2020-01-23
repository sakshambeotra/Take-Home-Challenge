import Firewall
import csv
from random import randint

#Returns true if ip1 is a smaller value than ip2
def smaller_ip(ip1,ip2):
	ip1 = [int(x) for x in ip1.split(".")]
	ip2 = [int(x) for x in ip2.split(".")]
	for i in range(4):
		if(ip1[i]>ip2[i]):
			return False
		else:
			return True
	return False

# Method that creates randomized rules
# NUM_ROWS: number of rules to create 
def create_tests(NUM_ROWS):
	with open('tests.csv', 'w', newline='') as csvfile:
	    write = csv.writer(csvfile, delimiter=',')
	    for i in range(NUM_ROWS):
	    	direction = "inbound" if randint(1,2)==1 else "outbound"
	    	protocol = "tcp" if randint(1,2)==1 else "udp"

	    	port = 0
	    	if randint(1,2) == 1:
	    		port1 = randint(1,65535)
	    		port2 = randint(1,65535)
	    		port = str(min(port1,port1))+"-"+str(max(port1,port2))
	    	else: 
	    		port = randint(1,65335)

	    	ip_address = ""
	    	if randint(1,2) == 1:
	    		ip1 = ""
	    		ip2 = ""
	    		for j in range(4):
	    			ip1 += str(randint(0,255))+"."
	    			ip2 += str(randint(0,255))+"."
	    		ip1 = ip1[:len(ip1)-1]
	    		ip2 = ip2[:len(ip2)-1]
	    		if(smaller_ip(ip1,ip2)):
	    			ip_address = ip1 + "-" + ip2
	    		else:
	    			ip_address = ip2 + "-" + ip1
	    	else:
	    		for j in range(4):
	    			ip_address += str(randint(0,255))+"."
	    		#remove the extra "." at the end
	    		ip_address = ip_address[:len(ip_address)-1]

	    	packet = [direction,protocol,port,ip_address]
	    	write.writerow(packet)

# Method that generates randomized inputs
# NUM_TESTS: number of tests to run
# test: Firewall oject
def run_tests(NUM_TESTS,test):
	for i in range(NUM_TESTS):
		direction = "inbound" if randint(1,2)==1 else "outbound"
		protocol = "tcp" if randint(1,2)==1 else "udp"
		port = randint(1,65535)

		ip_address = ""
		for j in range(4):
		    ip_address += str(randint(0,255))+"."
		#remove the extra "." at the end
		ip_address = ip_address[:len(ip_address)-1]

		print("TEST " + str(i) + " OUTPUT: " + str(test.accept_packet(direction,protocol,port,ip_address)))

def main():
	print("CREATING TESTS")
	create_tests(100)
	print("CREATING FIREWALL")
	test = Firewall.Firewall("tests.csv")
	print("RUNNING TESTS")
	run_tests(10,test)

if __name__ == '__main__':
    main()