import random
import time
from sympy import isprime, mod_inverse

def generate_prime(bits=2048):
    p = 1
    while not isprime(p):
        p = random.getrandbits(bits)
    return p

def generate_keys():
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537 
    d = mod_inverse(e, phi)

    return (e, n), (d, n)

def encrypt(message, public_key):
    e, n = public_key
    message_as_int = int.from_bytes(message.encode(), 'big')
    cipher = pow(message_as_int, e, n)
    return cipher

def decrypt(cipher, private_key):
    d, n = private_key
    message_as_int = pow(cipher, d, n)
    try:
        message_length = (message_as_int.bit_length() + 7) // 8
        message = message_as_int.to_bytes(message_length, 'big').decode()
    except OverflowError:
        message = "Decryption failed"
    return message

public_key, private_key = generate_keys()

message = "This is a message that is being encoded"
cipher = encrypt(message, public_key)
decrypted_message = decrypt(cipher, private_key)
print("Original:", message)
print("Decrypted:", decrypted_message)

def measure_decryption_time(cipher, private_key, iterations=100):
    times = []
    for _ in range(iterations):
        start_time = time.time()
        decrypt(cipher, private_key)
        end_time = time.time()
        times.append(end_time - start_time)
    return sum(times) / len(times)  

avg_time = measure_decryption_time(cipher, private_key)
print("Average decryption time:", avg_time)
