#!/usr/bin/env ruby

####################################################################################
# Server.rb: Accept and bounce encrypted messages to client using ECDHE AES128-GCM #
# Written by Levis                                                                 #
####################################################################################
require './tcpprotect'

SERVER_PORT = 2001

def handle_connect(client)
	puts "New client: #{client}"
	prot = TcpProtect.new(client)
	#--------- Handshake -----------#
	# Get Client Public key
	clientPub = prot.recv_f(MAGIC_BN_TAIL)
	# Calculate shared secret and set Encryption key
	prot.key_exchange(clientPub)
	# Export Server public key
	serverPub = prot.sign_msg(prot.format_pub)
	# Send it back to client, finish handshake
	prot.send_f(serverPub,MAGIC_BN_TAIL)
	#--------- End Handshake --------#
	# From now on, all data transferred between client and server are encrypted
	until prot.conn.closed? do
		begin
			# Send secure and Receive secure
			msg = prot.recv_s
			puts "[#{Time.now}] #{prot.conn.peeraddr[3]}: #{msg}"
			prot.send_s("You sent: #{msg}")
		rescue StandardError
			puts "Connection Closed #{prot.conn}"
			Thread.kill self
		end
	end
end


def startServer
	server = TCPServer.open(SERVER_PORT)
	puts "Server started on port #{SERVER_PORT}"
	while client = server.accept
		# New thread to handle new client
		Thread.new { handle_connect(client) }
	end
end

startServer