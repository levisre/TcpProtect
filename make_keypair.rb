# Create Keypair for use in RSA Encryption
require 'openssl'
# Set key size
KEY_SIZE = 2048
# Generate keypair
key_pair = OpenSSL::PKey::RSA.generate(KEY_SIZE)

pub_key = key_pair.public_key
# Export Private Key and Public Key to PEM format
File.open("private_key", "w") { |f| f.write(key_pair.to_pem) }
File.open("pubkey.pub", "w") { |f| f.write(pub_key.to_pem) }
