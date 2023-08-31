import pysodium, nacl.encoding, nacl.hash, inquirer, requests, base64, hashlib, base58
from Crypto.Hash import keccak

questions = [
	inquirer.Text('ons', message="ONS"),
	inquirer.List('type',
		message="ONS type",
		choices=['0 - Session ID', '1 - Wallet address', '2 - Lokinet'],
	)
]

answers = inquirer.prompt(questions)

name = answers["ons"].lower()
ons_type = int(answers["type"].split(" - ")[0])

def get_from_node(name_hash):
	headers = {
		'Content-Type': 'application/json',
	}

	json_data = {
		'jsonrpc': '2.0',
		'id': '0',
		'method': 'ons_resolve',
		'params': {
			'type': ons_type,
			'name_hash': base64.b64encode(name_hash).decode(),
		},
	}

	response = requests.post('http://public-na.optf.ngo:22023/json_rpc', headers=headers, json=json_data).json()
	return response["result"]

name_hash = nacl.hash.blake2b(name.encode(),encoder = nacl.encoding.RawEncoder)
onsinfo = get_from_node(name_hash)
nonce = bytes.fromhex(onsinfo["nonce"])
ciphertext = bytes.fromhex(onsinfo['encrypted_value'])
decryption_key = nacl.hash.blake2b(name.encode(), key=name_hash, encoder = nacl.encoding.RawEncoder)
val = pysodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext=ciphertext, ad=b'', nonce=nonce, key=decryption_key)

if ons_type == 0:
	print("Session ID: " + val.hex())
elif ons_type == 1:
	network = val[:1]
	if network == b'\x00':
		network = b'\x72'
	if network == b'\x01':
		network = b'\x74'
	if len(val) > 65:
		network = b'\x73'
	val = val[1:]
	keccak_hash = keccak.new(digest_bits=256)
	keccak_hash.update(network)
	keccak_hash.update(val)
	checksum = keccak_hash.digest()[0:4]
	val = network + val + checksum
	print("Wallet address: " + base58.encode(val.hex()))
elif ons_type == 2:
	val = base64.b32encode(val).decode()
	val = val.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "ybndrfg8ejkmcpqxot1uwisza345h769"))
	val = val.rstrip('=')
	val += ".loki"
	print("Lokinet address: " + val)
