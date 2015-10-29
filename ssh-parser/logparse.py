#/user/bin/env python
#This script was built with the log format of the sshd that comes with ubuntu
#It assumes the year is the current year

import time
import datetime


def parse_time(line):
	split_line = line.split(" ")
	#print split_line
	if split_line[1] == "":
		split_line.pop(1)

	time_bit = split_line[:3]


	the_time = time.strptime("%s %s %s %s" % (time_bit[0],time_bit[1],time_bit[2], datetime.date.today().year), "%b %d %H:%M:%S %Y")
	return the_time

def parse_password_fail(line):

	d = parse_time(line)
	split_line = line.split("Failed password for")
	
	our_bit = split_line[1]
	if our_bit.find(" invalid user ") == 0:
		info_bits_raw = our_bit[14:]
	else:
		info_bits_raw = our_bit.strip(" ")


	#print info_bits_raw

	info_bits_raw = info_bits_raw.split(" ")


	info_bits = {"user":info_bits_raw[0], "ip":info_bits_raw[2], "port":info_bits_raw[4], "date":d}
	return info_bits

def parse_invalid_user(line):

	d = parse_time(line)
	split_line = line.split("Invalid user ")

	#print split_line
	info_bits_raw = split_line[1].strip("\n")

	info_bits_raw = info_bits_raw.split(" from ")

	#print info_bits_raw

	info_bits = {"user":info_bits_raw[0], "ip":info_bits_raw[1], "port":None, "date":d}
	return info_bits


def get_ips(fails):
	
	ips = {}
	for line in fails:
		attacker_ip = line["ip"]

		if ips.has_key(attacker_ip):
			ips[attacker_ip] += 1
		else:
			ips[attacker_ip] = 1
	return ips

def get_usernames(fails):
	users = {}
	for line in fails:
		user = line["user"]

		if users.has_key(user):
			users[user] += 1
		else:
			users[user] = 1
	return users



if __name__ == "__main__":
	auth_log = open("auth.log","r")

	fails = []
	for line in auth_log:
		if "Failed password for" in line:
			fails.append( parse_password_fail(line) )
		elif "Invalid user " in line:
			fails.append( parse_invalid_user(line) )

	ips = get_ips(fails)
	for ip,times in ips.iteritems():
		print ip + " - " + str(times)
	users = get_usernames(fails)
	for user,times in users.iteritems():
		print user + " - " + str(times)
