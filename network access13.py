authorized_users ={
    "admin":"admin123",
    "user1":"password1", 
    "student":"student123"
}

def authenticate(username, password):
    if username in authorized_users:
        if authorized_users[username] == password:
            return True
        else:
            return False
    else:       
        return False
print("==Network Access Control System==")
username = input("Enter username: ")
password = input("Enter password: ")
if authenticate(username,password):
    print("Access granted, Welcome to the network!")
else:
    print("Access denied, Unauthorized user!")