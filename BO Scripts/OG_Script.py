#!/usr/bin/python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
	print "\nSending evil buffer..."
	s.connect(('10.11.23.12',110)) 	# connect to IP, POP3 port
	data = s.recv(1024) 		# receive banner
	print data 			# print banner

	s.send('USER test' +'\r\n') 	# send username "test"
	data = s.recv(1024) 		# receive reply
	print data 			# print reply

	s.send('PASS test\r\n') 	# send password "test"
	data = s.recv(1024) 		# receive reply
	print data 			# print reply

	s.close() 			# close socket
	print "\nDone!"
except:
	print "Could not connect to POP3!"