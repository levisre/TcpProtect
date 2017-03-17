require 'openssl'
require 'socket'

# Magic chars indicates ending of stream while sending BigNumber (used in Key Exchange)
MAGIC_BN_TAIL = "<BN\0"
# Magic chars indicates ending of stream while sending Encrypted Message
MAGIC_MSG_TAIL = "F!N\0"
TRUSTED = 0
PUBKEY = 1

class TcpProtect

	# Define connection to be protected
	attr_accessor :conn
	# Define Group name to be used in ECDH
	attr_accessor :ecGrp
	# Define shared secret key
	attr_reader	:csk
	# Define EC Instance
	attr_reader :ecInst

	def initialize(conn = nil,groupName="prime256v1")
		@csk = nil
		@ecGrp =  groupName
		@ecInst = OpenSSL::PKey::EC.generate(@ecGrp)
		@conn = conn
	end

	# Encrypt Message using AES128-GCM
	# NOTE: I use GCM Mode because it seem bo be fast and secure with additional Message Authentication
	# You can use any mode you want
	def encrypt_msg(msg)
		if msg.length > 0
			begin
				cipher = OpenSSL::Cipher::AES128.new(:GCM)
				cipher.encrypt
				cipher.key = @csk
				# randomize ID, will be sent alongside with encrypted data
				iv = cipher.random_iv
				# In this case, auth_data is unused, but required by GCM Mode
				cipher.auth_data = ''
				encrypted = cipher.update(msg) + cipher.final
				# Data being sent = auth_tag(16 bytes) + iv(12 bytes) + encrypteddata
				return cipher.auth_tag << iv << encrypted
			end
		else
			raise StandardError, "Message has Zero length"
		end
	end

	# Decrypt Message using AES128-GCM
	def decrypt_msg(msg)
		if msg.length > 0 
			begin
				# Get Auth tag = First 16 bytes
				tag = msg[0..15]
				# Get init vector = Next 12 bytes
				iv = msg[16..27]
				# Get Encrypted data = the rest
				data = msg[28..msg.length]
				cipher = OpenSSL::Cipher::AES128.new(:GCM)
				cipher.decrypt
				cipher.key = @csk
				cipher.iv = iv
				cipher.auth_tag = tag
				# In this case, auth_data is unused, but required by GCM Mode
				cipher.auth_data = ''
				return cipher.update(data) + cipher.final
			end
		else
			raise StandardError, "Message hash Zero length"
		end
	end

	# Sign message using SHA256 and RSA read from key file
	def sign_msg(msg)
		rsa = OpenSSL::PKey::RSA.new File.read 'private_key'
		digest = OpenSSL::Digest::SHA256.new
		if rsa.private?
			sign = rsa.sign digest, msg
			# Signed message = signature + original message
			return sign << msg
		else
			raise StandardError, 'Key is not private key'
		end
	end

	# Verify signed Message
	def verify_msg(msg)
		rsa = OpenSSL::PKey::RSA.new File.read 'pubkey.pub'
		digest = OpenSSL::Digest::SHA256.new
		# ------------ Deserialize message --------------#
		# len = rsa bit length / 8
		# For example, rsa 2048 will have len = 2048 bits -> to byte = 2048 / 8 = 256 byte
		# Therefore the first 256 bytes of message will be signature. the rest will be the datda
		# see sign_msg() for mor detail
		signLen = rsa.n.to_s(2).length
		sign = msg[0..signLen-1]
		data = msg[signLen..msg.length]
		# -------------- End Deserialization -------------#
		if rsa.public?
			# Return a list = [verifyResul: boolean, message: string]
			return rsa.verify(digest,sign,data), data
		else
			raise StandardError, 'Key is not a public key'
		end
	end

	# Calculate shared secret and set encryption key
	def key_exchange(partnerKey,base=0)
		begin
			cPubBN = OpenSSL::BN.new(partnerKey,base)
			cPubGrp = OpenSSL::PKey::EC::Group.new(@ecGrp)
			cPubPoint = OpenSSL::PKey::EC::Point.new(cPubGrp,cPubBN)
			shared = @ecInst.dh_compute_key(cPubPoint)
			# First 16 bytes of shared secret will be used as encryption key
			@csk = shared[0..15]
		rescue OpenSSL::PKey::ECError
			raise StandardError, 'Error in computing ECHDE'
		end
	end

	#Format message and send to peer
	def send_f(msg, delimiter=MAGIC_MSG_TAIL)
		@conn.write msg << delimiter
	end
	# send_s = Send Secured data (encryption and send)
	def send_s(msg, delimiter=MAGIC_MSG_TAIL)
		send_f(encrypt_msg(msg),delimiter)
	end

	#Receive formatted message from peer
	def recv_f(delimiter=MAGIC_MSG_TAIL)
		@conn.gets(delimiter).chomp(delimiter)
	end

	#recv_s = Receive Secured data (Receive and decryption)
	def recv_s(delimiter=MAGIC_MSG_TAIL)
		decrypt_msg(recv_f(delimiter))
	end

	#Export EC public key by base format (read docs about OpenSSL)
	def format_pub(base=0)
		@ecInst.public_key.to_bn.to_s(base)
	end
end
