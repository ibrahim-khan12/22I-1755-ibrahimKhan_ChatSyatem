Overview
This project implements a secure chat client that allows users to register and log in, encrypting their credentials and messages. The client communicates securely with the server using Diffie-Hellman key exchange for generating a shared secret and AES-128 encryption for protecting sensitive data.

Features
User Registration: Users can register with an email, a unique username, and a password. The credentials are encrypted and sent to the server.
User Login: Users can log in by providing their username and password, which are encrypted and sent securely.
Encryption: All sensitive data (email, username, password) is encrypted using AES-128 in CBC mode. Diffie-Hellman key exchange is used to generate a shared secret for secure communication.
Prerequisites
C++: Make sure you have a C++ compiler installed (G++ or Clang).
OpenSSL: This code uses the OpenSSL library for cryptographic functions like AES encryption and Diffie-Hellman key exchange. Ensure OpenSSL is installed on your system.
Install OpenSSL
On Ubuntu:

bash
Copy code
sudo apt-get install libssl-dev
On macOS (using Homebrew):

bash
Copy code
brew install openssl
How to Compile and Run
Clone the Repository:

Clone the repository or copy the source files to your local machine.

bash
Copy code
git clone https://github.com/your-username/secure-chat-client.git
cd secure-chat-client
Compile the Code:

Compile the C++ code using g++ or any C++ compiler that supports linking OpenSSL.

bash
Copy code
g++ -o chat_client chat_client.cpp -lssl -lcrypto
Run the Client:

After compilation, run the program:

bash
Copy code
./chat_client
Server Setup:

Make sure the server is running and listening on the correct port (8004 in this example). This client connects to 127.0.0.1:8004 by default.

Usage
Register a New User
When prompted, enter your email address, a unique username, and a password.
The credentials will be encrypted and sent to the server for registration.
If the username is already taken, you will be prompted to try again.
Login
After registration, log in by providing your username and password.
The credentials are encrypted using AES-128 and sent to the server for verification.
Encryption Details
AES-128 Encryption: The Advanced Encryption Standard (AES) in 128-bit CBC mode is used to encrypt user data. A pre-shared key or a key derived from Diffie-Hellman is used for the encryption.
Diffie-Hellman Key Exchange: This algorithm is used to securely exchange a shared secret between the client and the server, ensuring that all communication is encrypted.
SHA-256 Hashing: Passwords are hashed using SHA-256 on the server side, combined with a unique salt for each user to ensure security.
File Structure
chat_client.cpp: The main client-side code that handles user registration, login, and encrypted communication with the server.
Security Measures
Confidentiality: All sensitive user information (email, username, password) is encrypted before transmission.
Password Hashing: Passwords are hashed on the server using SHA-256, preventing storage of plaintext passwords.
Salting: Unique salts are used for each user during hashing to mitigate rainbow table attacks.
Limitations and Future Improvements
Error Handling: The current error handling is minimal. Future versions should include more detailed error messages and handling for network issues.
Server-Side Code: This client is designed to work with a corresponding server. Ensure the server implements proper decryption and handling of encrypted messages.
Additional Features: Future versions could include support for message encryption between users, improved UI, and better validation.
