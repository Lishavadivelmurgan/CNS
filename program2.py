import os
import hashlib

def hash_password(password):
    #Generate random salt(16 bytes)
    salt = os.urandom(16)

    #Combine password + salt
    salted_password = password.encode() + salt

    #Hash using SHA-256
    hash_value = hashlib.sha256(salted_password).hexdigest()

    return salt, hash_value

def verify_password(input_password, stored_salt, stored_hash):
    salted_input = input_password.encode() + stored_salt
    new_hash = hashlib.sha256(salted_input).hexdigest()

    return new_hash == stored_hash

if __name__ == "__main__":
    password = input("Enter password: ")

    salt, hashed = hash_password(password)

    print("\nLogin Verification")

    login_password = input("Re-enter password: ")

    if verify_password(login_password, salt, hashed):
        print("Password Verified")
    else:
        print("Wrong password")