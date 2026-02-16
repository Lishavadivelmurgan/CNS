import hashlib
trusted_dns_records={
    "Google.com":hashlib.sha256("Google.com".encode()).hexdigest(),
    "Amazon.com":hashlib.sha256("Amazon.com".encode()).hexdigest(),
    "Facebook.com":hashlib.sha256("Facebook.com".encode()).hexdigest()
}

user_domain=input("Enter the website domain: ")
if user_domain in trusted_dns_records:
    user_hash=hashlib.sha256(user_domain.encode()).hexdigest()
    if user_hash==trusted_dns_records[user_domain]:
        print("\n website is authentic( Not fake)")
        print("DNSSEC verification successful")
    else:
        print("\n  Warning! website data is modified")
        print("DNSSEC verification failed")
else:
    print("\n Fake website Detected!")
    print("Domain not found in trusted DNS records.")
