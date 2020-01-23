import csv

class Rule:
	# Constructor
	# validInputs: A list that holds all valid input values that a packet could have
	def __init__(self,validInputs):
		self.isBlocked = {}

		for element in validInputs:
			self.isBlocked[element] = []

	# Update the object with values that are allowed through the firewall
	# allowedValues: list of rules allowed through the firewall
	def allowValues(self,allowedValues):
		for element,row in allowedValues:
			if str(element).isnumeric():
				element = int(element)
			self.isBlocked[element].append(row)

	# Returns a list of rules that match the packet
	# packet: a value that we want to make sure is allowed through firwall 
	def accept_packet(self,packet):
		return self.isBlocked[packet]

class Firewall:
	# Constructor
	# rules_csv: a list of all the rules
	def __init__(self,rules_csv):

		allowedValues = [[] for i in range(7)]

		rowNum = 0
		#parse the rules
		with open(rules_csv) as csvfile:
		    readCSV = csv.reader(csvfile, delimiter=',')
		    for row in readCSV:

		    	#Add the directions and protocols to allowedValues
		    	for i in range(2):
		    		allowedValues[i].append((row[i],rowNum))

		    	#Add port to allowedValues
		    	allowedValues[2].append((rowNum,row[2]))

		    	ip_address = row[3]

		    	#Check if ip address is a range
		    	if "-" in ip_address:
		    		ip_address = ip_address.split("-")
		    		ip_address1 = [int(x) for x in ip_address[0].split(".")]
		    		ip_address2 = [int(x) for x in ip_address[1].split(".")]

		    		previous_val = ip_address1[3]

		    		#Add all values in range to firewall exception
		    		for i in reversed(range(4)):
		    			allowedValues[i+3].append((str(ip_address1[i]),rowNum))
		    			while(ip_address1[i] != ip_address2[i]):
			    			allowedValues[i+3].append((str(ip_address1[i]),rowNum))
			    			if ip_address1[i]==ip_address2[i]:
			    				continue
			    			ip_address1[i]+=1
			    			if ip_address1[i]==256:
			    				ip_address1[i] = 0
		    	else:
		    		ip_address = ip_address.split(".")
		    		for i in range(4):
		    			allowedValues[i+3].append((ip_address[i],rowNum))
		    	rowNum += 1

		#add more rules here if needed

		self.rules = []
		self.rules.append(Rule(["inbound","outbound"])) #Direction rule
		self.rules.append(Rule(["tcp","udp"])) #Protocol rule
		self.rules.append(Rule([i for i in range(rowNum)])) #Port rules
		self.rules.append(Rule([i for i in range(256)])) #IP address will have 4 rules, one for each octet
		self.rules.append(Rule([i for i in range(256)]))
		self.rules.append(Rule([i for i in range(256)]))
		self.rules.append(Rule([i for i in range(256)])) 

		for i in range(len(self.rules)):
			self.rules[i].allowValues(allowedValues[i])

	# Check if a packet is allowed through the firewall
	def accept_packet(self,direction,protocol,port,ip_address):
		ip_address = [int(x) for x in ip_address.split(".")]
		packet = [direction,protocol,port]
		packet += ip_address

		#Store the possible rules that match all inputs except port
		possibleRules = []
		for i in range(len(self.rules)):
			if i == 2:
				continue
			possibleRules.append(set(self.rules[i].accept_packet(packet[i])))


		#Check the corresponsing ports for all the narrowed down possible rules and see if input port matches any of them
		for rule in set.intersection(*possibleRules):
			portStart = self.rules[2].accept_packet(rule)[0]
			portEnd = 65535

			if "-" in portStart:
				ports = [int(x) for x in portStart.split("-")]
				portStart = ports[0]
				portEnd = ports[1]

			portStart = int(portStart)

			if port >= portStart and port <= portEnd:
				print(packet,"matched rule: ",rule)
				return True
		print(packet,"no matching rule found")
		return False