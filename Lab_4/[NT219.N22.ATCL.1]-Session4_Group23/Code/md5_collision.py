import hashlib

def md5_collision():
    message1 = b'hello'
    message2 = b'world'

    hash1 = hashlib.md5(message1).digest()
    hash2 = hashlib.md5(message2).digest()

    for i in range(1, 50):
        for j in range(1, 50):
            padded_message1 = message1 + b'\x80' + b'\x00'*(i-1) + hash1
            padded_message2 = message2 + b'\x80' + b'\x00'*(j-1) + hash2

            new_hash1 = hashlib.md5(padded_message1).digest()
            new_hash2 = hashlib.md5(padded_message2).digest()

            if new_hash1 == new_hash2:
                print("Collision found:")
                print(f"Message 1: {padded_message1}")
                print(f"Message 2: {padded_message2}")
                print(f"Hash: {new_hash1.hex()}")
                return

md5_collision()
