Write a Python program to implement Caesar Cipher encryption with a shift value of 3. The program should take the plaintext as
input from the user and display the corresponding encrypted text as output.


def caesar_cipher_encrypt(plain_text, shift):
    encrypted_text = ""
    
    for char in plain_text:
        if char.isalpha():
            if char.isupper():
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            
            encrypted_text += encrypted_char
        else:
            encrypted_text += char

    return encrypted_text

plain_text = input("Enter the text to encrypt: ")
shift = int(input("Enter the shift value: "))

encrypted_text = caesar_cipher_encrypt(plain_text, shift)

print("Encrypted text:", encrypted_text)
