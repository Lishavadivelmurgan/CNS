import hashlib

def sign_data(data):
    return hashlib.sha256(data.encode()).hexdigest()
original_domain = input("Enter original domain name: ")

signature = sign_data(original_domain)
print("\nGenerated DNS Signature:", signature)

received_domain = input("Enter received domain name: ")

verify_signature=sign_data(received_domain)
if verify_signature == signature:
    print("\nDNSSEC verification successful: Data i s authentic.")
else:
    print("\nDNSSEC verification failed: Data has been modified.")


