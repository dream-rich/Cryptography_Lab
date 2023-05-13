import hashlib

message = b'This is the original message'
h = hashlib.sha256(message).hexdigest()

new_message = b'This is the new message'
length = len(message) + len(new_message)
padding = b'\x80' + b'\x00' * (55 - (length + 1) % 64) + length.to_bytes(8, byteorder='big')

h2 = hashlib.sha256(new_message + padding).hexdigest()

print(f"h: {h}")
print(f"h2: {h2}")
