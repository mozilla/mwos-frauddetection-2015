import sys
import os
import csv

# read from CSV file : IP values(till before the IP port number) and start time and specify a time window
# algorithm: Read IP values --> Create a Unique list --> then search the start times for their corresponding IP entries 
#--> if a match, then push into the dictionary corresponding the IP address --> Compare for time windows.


def read_csvfile_IP(inputfile):

	list_of_ips = []

	with open(inputfile, 'rb') as i_file:
		next(i_file)
		for line in i_file:
			line = line.split(',')

			list_of_ips.append(line[2]) #ips are inserted along with their port numbers
		
	#print list_of_ips

	for ip in list_of_ips:
		ip = ip.rsplit(':', 1)[0]
		list_of_ips.append(ip)

	return list_of_ips


if __name__ == '__main__':

	inputfile = sys.argv[1]
	outfile = sys.argv[2]

	list_of_ips = []
	list_of_ips = read_csvfile_IP(inputfile) #read csv file and print IPs.

	with open(outfile, 'wb') as o_file:
		for ip in list_of_ips:
			o_file.write(ip)
