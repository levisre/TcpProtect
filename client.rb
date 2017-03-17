#!/usrbin/env ruby

############################################################################
# client.rb: Establish a secure channel with server using ECDHE AES128-GCM #
# Written by Levis                                                         #
############################################################################
require './tcpprotect'

HOST_ADDR = 'localhost'
HOST_PORT = 2001

def tcpClient
	conn = TCPSocket.open(HOST_ADDR,HOST_PORT)
	prot = TcpProtect.new(conn)
	#--------- Handshake -----------#
	# export Client Public key
	clientPub = prot.format_pub
	# Send client Public key to server
	prot.send_f(clientPub,MAGIC_BN_TAIL)
	# Receive server public key
	signedData = prot.recv_f(MAGIC_BN_TAIL)
	verify = prot.verify_msg(signedData)
	isTrusted = verify[TRUSTED]
	serverPub = verify[PUBKEY]
	# Verify OK?
	if isTrusted then
		begin
			# Calculate shared secret and set Encryption key
			prot.key_exchange(serverPub)
			# Send sample message to server
			prot.send_s("Handshaking finished")
			#--------- End Handshake --------#
			# From now on, all data transferred between server and client are encrypted
			until prot.conn.closed? do
				begin
					# Send Secure and Receive Secure
					puts prot.recv_s
					print "Msg>"
					text = gets.chomp
					prot.send_s(text)
				rescue SystemExit, Interrupt
					puts "Closing connection"
					conn.close
				end
			end
		end
	# if verification Fails
	else
		puts "Could not verify server public key? Is it trusted?"
		conn.close
	end
end

tcpClient