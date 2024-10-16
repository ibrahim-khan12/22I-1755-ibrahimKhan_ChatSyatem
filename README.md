# **Secure Chat Client**

## **Overview**

The Secure Chat Client is a C++ application designed for secure communication between a client and server. It allows users to register and log in using encrypted credentials, ensuring the confidentiality and integrity of sensitive information. The system leverages **Diffie-Hellman key exchange** for secure key generation and **AES-128 encryption** for encrypting user data and messages.

This client is built with robust security measures such as password hashing, salting, and symmetric key encryption, and it's designed to interact with a corresponding server that handles user authentication and encrypted communication.

## **Key Features**

- **User Registration**: Securely register new users by providing a unique email, username, and password.
- **User Login**: Authenticate users by verifying encrypted credentials.
- **Encrypted Communication**: Secure exchange of user credentials and chat messages using AES-128 encryption and keys derived from the Diffie-Hellman key exchange.
- **Password Security**: User passwords are hashed using SHA-256 and salted, ensuring they are never stored in plaintext.
- **Credential Storage**: Encrypted user credentials are securely stored on the server side.

## **Technical Details**

### **Encryption and Security**
- **AES-128 (CBC Mode)**: Used to encrypt user credentials (email, username, password) and chat messages.
- **Diffie-Hellman Key Exchange**: A secure method for exchanging cryptographic keys over an insecure channel.
- **SHA-256 with Salt**: Used for hashing passwords before they are stored on the server. A unique salt is generated for each user to ensure password hash uniqueness.
- **OpenSSL**: Utilized for all cryptographic operations including AES encryption, Diffie-Hellman key exchange, and hashing.

## **System Requirements**

- **C++ Compiler**: GCC or Clang supporting C++11 or higher.
- **OpenSSL Library**: Ensure OpenSSL is installed on your system to provide cryptographic functionality.

### **OpenSSL Installation**
- **Ubuntu/Debian**:
  ```bash
  sudo apt-get install libssl-dev
macOS (via Homebrew):

bash
Copy code
brew install openssl
Windows: Install OpenSSL for Windows.

Installation Instructions
Clone the Repository:

bash
Copy code
git clone https://github.com/your-username/secure-chat-client.git
cd secure-chat-client
Compile the Code:

```bash
Copy code
g++ -o chat_client chat_client.cpp -lssl -lcrypto
Run the Client:
```

```bash
Copy code
./chat_client
Server Setup: Ensure the server is running on 127.0.0.1:8004 to accept client connections.
```

Usage Instructions
1. Registering a New User
On startup, the client presents a menu. Select the option to register a new user.
Input your email, a unique username, and a secure password. The data will be encrypted and sent to the server for registration.
If the username is already taken, you'll be prompted to enter a new one.
2. Logging In
To log in, select the login option and provide your username and password.
The credentials will be encrypted using the shared key from the Diffie-Hellman exchange and securely sent to the server for verification.
3. Encrypted Communication
Once logged in, users can exchange messages securely. Every message is encrypted using AES-128.
File Structure
chat_client.cpp: Main client-side code that implements user registration, login, Diffie-Hellman key exchange, and AES-128 encryption.
creds.txt (server-side): Stores encrypted user credentials (email, username, hashed password, and salt).
