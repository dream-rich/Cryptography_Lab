from base64 import b64decode
from Crypto.Cipher import DES

def decrypt_des(key, iv, ciphertext):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(b'\0')

def main():
    ciphertext = b64decode("jtEl85W3Riqjk56bj+7J5YcYhHvzHc6d")
    iv = b64decode("VyUR14UQP/0=")
    key = b"\xE0\xE0\xE0\xE0\xF1\xF1\xF1\xF1"

    plaintext = decrypt_des(key, iv, ciphertext)
    print("Plaintext:", plaintext.decode('utf-8'))

if __name__ == '__main__':
    main()