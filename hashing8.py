import hashlib

def hash_string(text):
    hasher = hashlib.sha256()
    hasher.update(text.encode())
    return hasher.hexdigest()

text=input("Enter the text to hash: ")

hash_value = hash_string(text)

print("Original text:", text)
print("SHA-256 hash:", hash_value)