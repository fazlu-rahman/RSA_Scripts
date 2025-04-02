###
# This script act as a middleware which captures the outgoing request sent to RSA Authentication Manager by applications. There are some applications which do not prompt for PASSCODE (After entering USERNAME and PASSWORD) with Radius authentication.
# Run this script in a SERVER and configure the application to point to this SERVER IP and use SHARED SECRET configured in RSA Authentication Manager for Radius Client for the application
# Create/Update a Radius Client under RSA Authentication Manager with this SERVER IP
# In the Radius configuration of application, use this SERVER IP as Radius server
# Once configured, from the application login page, enter your USERNAME and Username and PASSWORDPASSCODE (without any space) under Passcode/Password field of application
# Upon getting the request by script, it will decrypt the request and separate PASSWORD and PASSCODE. Then sent request to RSA Authentication Manager with USERNAME & PASSWORD after encrypting. Once received CHALLENGE request back from RSA Authentication Manager, script will then sent another request with USERNAME & PASSCODE to RSA Authentication Manager. The final response from RSA will sent back to the application for login.
###

import socket
import struct
import hashlib

SHARED_SECRET = b"SHARED_SECRET_CONFIGURED_IN_RSA_FOR_THE_APPLICATION_HERE"

MIDDLEWARE_IP = "0.0.0.0"
MIDDLEWARE_PORT = 1812

RSA_SERVER_IP = "RSA_AUTHENTICATION_MANAGER_SERVER_IP_HERE"
RSA_SERVER_PORT = 1812

def decrypt_user_password(encrypted_password, request_authenticator, shared_secret):
	if len(encrypted_password) % 16 != 0:
		raise ValueError("Encrypted password length must be a multiple of 16 bytes")
		
	decrypted_password = b""
	last_hash = request_authenticator
	
	for i in range(0, len(encrypted_password), 16):
		block = encrypted_password[i:i+16]
		md5_hash = hashlib.md5(shared_secret + last_hash).digest()
		decrypted_block = bytes([block[j] ^ md5_hash[j] for j in range(16)])
		decrypted_password += decrypted_block
		last_hash = block
		
	return decrypted_password.rstrip(b"\x00").decode()

def encrypt_user_password(password, request_authenticator, shared_secret):
	padded_password = password.encode().ljust(16 * ((len(password) + 15) // 16), b"\x00")
	encrypted_password = b""
	last_hash = request_authenticator
	
	for i in range(0, len(padded_password), 16):
		block = padded_password[i:i+16]
		md5_hash = hashlib.md5(shared_secret + last_hash).digest()
		encrypted_block = bytes([block[j] ^ md5_hash[j] for j in range(16)])
		encrypted_password += encrypted_block
		last_hash = encrypted_block
		
	return encrypted_password

def parse_radius_packet(packet_data):
	radius_header = packet_data[:20]
	code, identifier, length, request_authenticator = struct.unpack("!BBH16s", radius_header)
	attributes = packet_data[20:length]
	user_password_encrypted = None
	username = None
	state_attribute = None
	
	while attributes:
		attr_type = attributes[0]
		attr_length = attributes[1]
		attr_value = attributes[2:attr_length]
		if attr_type == 1:
			username = attr_value.decode()
		elif attr_type == 2:
			user_password_encrypted = attr_value
		elif attr_type == 24:
			state_attribute = attr_value
		
		attributes = attributes[attr_length:]
		
	return code, identifier, request_authenticator, username, user_password_encrypted, state_attribute

def send_radius_request(username, password_or_passcode, request_authenticator, state=None):
	rsa_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	code = 1
	identifier = 0x01
	attributes = b""
	username_attr = struct.pack("!BB", 1, len(username) + 2) + username.encode()
	encrypted_password_or_passcode = encrypt_user_password(password_or_passcode, request_authenticator, SHARED_SECRET)
	password_attr = struct.pack("!BB", 2, len(encrypted_password_or_passcode) + 2) + encrypted_password_or_passcode
	
	if state:
		state_attr = struct.pack("!BB", 24, len(state) + 2) + state
		attributes += state_attr
		
	attributes += username + password_attr
	
	length = 20 + len(attributes)
	radius_header = struct.pack("!BBH16s", code, identifier, length, request_authenticator)
	radius_packet = radius_header + attributes
	rsa_socket.sendto(radius_packet, (RSA_SERVER_IP, RSA_SERVER_PORT))
	response_packet, _ = rsa_socket.recvfrom(4096)
	return response_packet

def forward_request_to_client(client_socket, client_address, response_packet):
	client_socket.sendto(response_packet, client_address)
	
def middleware():
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server_socket.bind((MIDDLEWARE_IP, MIDDLEWARE_PORT))
	print(f"Middleware listening on {MIDDLEWARE_IP}:{MIDDLEWARE_PORT}...")
	
	while True:
		data, client_address = server_socket.recvfrom(4096)
		print(f"Received RADIUS request from {client_address}")
		try:
			code, identifier, request_authenticator, username, encrypted_password, state = parse_radius_packet(data)
			if not username or not encrypted_password:
				print("Invalid RADIUS packet: Missing required fields")
				continue
				
			decrypted_credentials = decrypt_user_password(encrypted_password, request_authenticator, SHARED_SECRET)
			password = decrypted_credentials[:-8]
			passcode = decrypted_credentials[-8:]
			
			if len(passcode) != 8 or passcode.isdigit():
				print("Invalid passcode format. Must be 8 digits")
				continue
				
			rsa_response = send_radius_request(username, password, request_authenticator)
			rsa_code, rsa_identifier, rsa_length, rsa_authenticator = struct.unpack("!BBH16s", rsa_response[:20])
			if rsa_code == 11:
				print("Received CHALLENGE Request from RSA")
				_, _, _, _, _, state = parse_radius_packet(rsa_response)
				final_response = send_radius_packet(username, passcode, request_authenticator, state)
				forward_response_to_client(server_socket, client_address, final_response)
				print("Final response forwarded to client")
			elif rsa_code == 2:
				print("Authentication successful")
				forward_response_to_client(server_socket, client_address, rsa_response)
			elif rsa_code == 3:
				print("Authentication failed")
				forwarded_response_to_client(server_socket, client_address, rsa_response)
			else:
				print(f"Unexpected RSA response code: {rsa_code}")
		except Exception as e:
			print(f"Error processing RADIUS packet: {e}")
	
if __name__ == "__main__":
	middleware()
