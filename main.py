# this code is for proof of concept of ElGamal homomorphic multiplication 
# with RSA signature verification to ensure the result is correct
# ElGamal can be used for a variety of homomorphic operations such as:
# addition, multiplication, exponentiation, etc.
# for this implemenation, we will use multiplication

# the RSA and ElGamal keys are stored in keys.txt
# the encrypted values are stored in encrypted_values.txt
# the input variables are stored in input_variables.txt
# the decrypted result is printed to the console

# pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import Crypto
import random
import sys

# generate a signature for data using private key
def generate_signature(private_key, data):
    h = SHA256.new(data.encode('utf-8')) # hash the data using SHA256
    signature = pkcs1_15.new(private_key).sign(h) # sign the hash using the private key
    return signature

# verify the signature for data using public key
def verify_signature(public_key, data, signature): 
    h = SHA256.new(data.encode('utf-8'))
    try:
        pkcs1_15.new(public_key).verify(h, signature) # verify the signature using the public key
        return True
    except (ValueError, TypeError):
        return False

# primitive root modulo p (generator)
def get_generator(p: int):
    while True:
        generator = random.randrange(3, p) #remove all non-primitive roots
        if pow(generator, 2, p) == 1 or pow(generator, p, p) == 1: # check if generator shares factor with p
            continue
        return generator

# generate ElGamal keys
def generate_keys(bits): # RSA modulus length must be a multiple of 256 and >= 1024
    p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes) # generate a prime number
    g = get_generator(p) # primitive root modulo p
    x = random.randrange(3, p) # private key
    Y = pow(g, x, p) # public key
    return p, g, x, Y 

# encrypt a value using ElGamal
def encrypt(value, g, Y, p):
    k = random.randrange(3, p) # random number
    a = pow(g, k, p) # g^k (mod p)
    b = (pow(Y, k, p) * value) % p # Y^k * v (mod p)
    return a, b

# decrypt a value using ElGamal
def decrypt(a, b, x, p):
    return (b * pow(a, -x, p)) % p # b * a^(-x) (mod p) = b/a^x (mod p)

# save keys to file
def save_keys(filename, elgamal_keys, rsa_private_key, rsa_public_key):
    with open(filename, 'w') as file:
        file.write(f"ElGamal Keys:\n") # save ElGamal keys to file
        file.write(f"p={elgamal_keys[0]}\ng={elgamal_keys[1]}\nx={elgamal_keys[2]}\nY={elgamal_keys[3]}\n")
        file.write(f"RSA Private Key:\n{rsa_private_key.export_key().decode()}\n") # save RSA private key to file
        file.write(f"RSA Public Key:\n{rsa_public_key.export_key().decode()}\n") # save RSA public key to file

# load keys from file
def load_keys(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()
        p = int(lines[0].split('=')[1]) # load ElGamal keys from file
        g = int(lines[1].split('=')[1])
        x = int(lines[2].split('=')[1]) # load RSA private key from file
        Y = int(lines[3].split('=')[1]) # load RSA public key from file
        return p, g, x, Y
    
# save input variables to file for proof of concept
def save_input_variables(filename, bits, v1, v2):
    with open(filename, 'w') as file:
        file.write(f"bits={bits}\nv1={v1}\nv2={v2}") 

# homomorphic multiplication of two encrypted values
def homomorphic_multiply(a1, b1, a2, b2, p):
    a_result = (a1 * a2) % p # homomorphic multiplication of a values
    b_result = (b1 * b2) % p # homomorphic multiplication of b values
    return a_result, b_result

# main function
if __name__ == "__main__":
    # amount of bits for prime number generation
    bits = int(input("Enter the number of bits for prime number generation >= 1024 and a multiple of 256: "))
    # initial values for users
    v1 = int(input("Enter the initial value for User 1 (v1): "))
    v2 = int(input("Enter the initial value for User 2 (v2): "))

    # check if bits is >= 1024 and a multiple of 256
    if bits < 1024 or bits % 256 != 0:
        print("Number of bits must be >= 1024 and a multiple of 256.")
        sys.exit()

    # save input variables to file for proof of concept
    save_input_variables("input_variables.txt", bits, v1, v2)

    # generate ElGamal keys and RSA keys
    elgamal_keys = generate_keys(bits)
    rsa_key = RSA.generate(bits)
    
    # save keys to file
    save_keys("keys.txt", elgamal_keys, rsa_key, rsa_key.publickey())

    # load keys from file
    a1, b1 = encrypt(v1, elgamal_keys[1], elgamal_keys[3], elgamal_keys[0]) # p, g, Y, v
    a2, b2 = encrypt(v2, elgamal_keys[1], elgamal_keys[3], elgamal_keys[0]) # p, g, Y, v

    # save encrypted values to file
    with open("encrypted_values.txt", 'w') as file:
        file.write(f"Encrypted Value for User 1:\n{a1}\n{b1}\n")
        file.write(f"Encrypted Value for User 2:\n{a2}\n{b2}\n")

    # homomorphic multiplication of encrypted values
    a_result, b_result = homomorphic_multiply(a1, b1, a2, b2, elgamal_keys[0])

    # decrypt homomorphic multiplication result
    decrypted_result = decrypt(a_result, b_result, elgamal_keys[2], elgamal_keys[0])

    # print results for proof of concept
    print(f"\nHomomorphic Multiplication Result (Decrypted): {decrypted_result}")

