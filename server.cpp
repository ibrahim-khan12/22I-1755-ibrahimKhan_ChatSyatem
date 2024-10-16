


#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/bn.h>       // For Diffie-Hellman
#include <openssl/sha.h>      // For hashing passwords
#include <openssl/rand.h>     // For generating salt
#include <fstream>
#include <sstream>
#include <vector>

using namespace std;

const int p = 23;  // Prime number (public parameter)
const int g = 5;   // Primitive root (public parameter)
BIGNUM *shared_secret = nullptr;  // Shared secret key

// Generate a random private key (server-side)
BIGNUM* generate_private_key()
{
    BIGNUM *private_key = BN_new();
    BN_rand(private_key, 128, 0, 0);  // Generate a random 128-bit private key
    return private_key;
}

// Compute public key (g^private_key % p)
BIGNUM* compute_public_key(BIGNUM *private_key)
{
    BIGNUM *g_bn = BN_new();
    BIGNUM *p_bn = BN_new();
    BIGNUM *public_key = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_set_word(g_bn, g);
    BN_set_word(p_bn, p);

    // public_key = g^private_key % p
    BN_mod_exp(public_key, g_bn, private_key, p_bn, ctx);

    BN_free(g_bn);
    BN_free(p_bn);
    BN_CTX_free(ctx);

    return public_key;
}

// Send a public key to the client
void send_public_key(int client_socket, BIGNUM *public_key)
{
    char *public_key_str = BN_bn2hex(public_key);
    send(client_socket, public_key_str, strlen(public_key_str), 0);
    OPENSSL_free(public_key_str);
}

// Receive public key from client
BIGNUM* receive_public_key(int client_socket)
{
    char buf[256];
    recv(client_socket, buf, sizeof(buf), 0);
    BIGNUM *client_public_key = BN_new();
    BN_hex2bn(&client_public_key, buf);
    return client_public_key;
}

// Compute shared secret using client's public key
BIGNUM* compute_shared_secret(BIGNUM *client_public_key, BIGNUM *private_key)
{
    BIGNUM *p_bn = BN_new();
    BIGNUM *shared_secret = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_set_word(p_bn, p);

    // shared_secret = client_public_key^private_key % p
    BN_mod_exp(shared_secret, client_public_key, private_key, p_bn, ctx);

    BN_free(p_bn);
    BN_CTX_free(ctx);

    return shared_secret;
}

// Perform Diffie-Hellman Key Exchange (Server-Side)
void diffie_hellman_key_exchange(int client_socket)
{
    // 1. Generate private key
    BIGNUM *private_key = generate_private_key();
    cout << "Server: Private key generated." << endl;

    // 2. Compute public key (g^private_key % p)
    BIGNUM *public_key = compute_public_key(private_key);
    cout << "Server: Public key generated." << endl;

    // 3. Send public key to the client
    send_public_key(client_socket, public_key);
    cout << "Server: Public key sent to client." << endl;

    // 4. Receive client's public key
    BIGNUM *client_public_key = receive_public_key(client_socket);
    cout << "Server: Client's public key received." << endl;

    // 5. Compute shared secret
    shared_secret = compute_shared_secret(client_public_key, private_key);
    cout << "Server: Shared secret computed." << endl;

    // Cleanup
    BN_free(private_key);
    BN_free(public_key);
    BN_free(client_public_key);
}

// Helper function to hash a password using SHA-256 with a salt
string hash_password_with_salt(const string &password, const string &salt)
{
    string combined = password + salt;  // Combine password and salt

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)combined.c_str(), combined.length(), hash);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << hex << (int)hash[i];
    }

    return ss.str();
}

// Helper function to generate a random salt (32-bit length)
string generate_salt()
{
    unsigned char salt[4];  // 32-bit (4 bytes) salt
    RAND_bytes(salt, sizeof(salt));

    stringstream ss;
    for (int i = 0; i < sizeof(salt); ++i) {
        ss << hex << (int)salt[i];
    }

    return ss.str();
}

// Check if a username or email is unique in creds.txt
bool is_unique(const string &username, const string &email)
{
    ifstream file("creds.txt");
    string line;
    while (getline(file, line)) {
        istringstream iss(line);
        string stored_email, stored_username, stored_password, stored_salt;
        iss >> stored_email >> stored_username >> stored_password >> stored_salt;

        if (stored_username == username || stored_email == email) {
            return false;  // Username or email already exists
        }
    }
    return true;  // Unique
}

// Save new user credentials to creds.txt
void save_credentials(const string &email, const string &username, const string &hashed_password, const string &salt)
{
    ofstream file("creds.txt", ios::app);
    file << "email: " << email << ", username: " << username 
         << ", password: " << hashed_password << ", salt: " << salt << endl;
}

// Handle user registration process
void handle_registration(int client_socket)
{
    char buf[256];

    // Receive encrypted registration info (email, username, password) from the client
    recv(client_socket, buf, sizeof(buf), 0);

    // Decrypt the received information using shared_secret 
    string registration_info(buf);
    istringstream iss(registration_info);
    string email, username, password;
    iss >> email >> username >> password;

    cout << "Server: Received registration info - Email: " << email << ", Username: " << username << endl;

    // Check if the username or email is unique
    if (!is_unique(username, email)) {
        string error_message = "Username or email already exists. Please choose another one.";
        send(client_socket, error_message.c_str(), error_message.length(), 0);
        return;
    }

    // Generate a random salt
    string salt = generate_salt();
    cout << "Server: Generated salt: " << salt << endl;

    // Hash the password with the salt
    string hashed_password = hash_password_with_salt(password, salt);

    // Save the credentials to creds.txt
    save_credentials(email, username, hashed_password, salt);

    // Send success message to the client
    string success_message = "Registration successful!";
    send(client_socket, success_message.c_str(), success_message.length(), 0);
}
// Handle user login process
void handle_login(int client_socket)
{
    char buf[256];
// Receive encrypted login info (username, password) from the client
recv(client_socket, buf, sizeof(buf), 0);

// Decrypt the received information using shared_secret
// For simplicity, let's assume the decryption function is decrypt_with_shared_secret
string encrypted_login_info(buf);
string login_info = encrypted_login_info; // Placeholder for actual decryption logic

istringstream iss(login_info);
string username, password;
iss >> username >> password;
    recv(client_socket, buf, sizeof(buf), 0);


    cout << "Server: Received login info - Username: " << username << endl;

    // Retrieve stored credentials from creds.txt
    ifstream file("creds.txt");
    string line, stored_email, stored_username, stored_password, stored_salt;
    bool user_found = false;

    while (getline(file, line)) {
        istringstream iss(line);
        iss >> stored_email >> stored_username >> stored_password >> stored_salt;

        if (stored_username == username) {
            user_found = true;
            break;
        }
    }

    if (!user_found) {
        string error_message = "Username not found.";
        send(client_socket, error_message.c_str(), error_message.length(), 0);
        return;
    }

    // Hash the entered password with the stored salt
    string hashed_password = hash_password_with_salt(password, stored_salt);

    // Compare the hashed password with the stored hashed password
    if (hashed_password == stored_password) {
        string success_message = "Login successful! Access granted to the chat system.";
        send(client_socket, success_message.c_str(), success_message.length(), 0);
    } else {
        string error_message = "Incorrect password. Access denied.";
        send(client_socket, error_message.c_str(), error_message.length(), 0);
    }
}

int main() {
    char buf[256];
    int server_socket, client_socket;
    struct sockaddr_in server_address;

    cout << "\n\t>>>>>>>>>> XYZ University Chat Server <<<<<<<<<<\n\n";

    // Create the server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        cerr << "Failed to create socket.\n";
        exit(1);
    }

    // Define the server address
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8004);
    server_address.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket to the specified IP and port
    if (bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address)) == -1) {
        cerr << "Failed to bind to the port.\n";
        close(server_socket);
        exit(1);
    }

    // Listen for incoming connections (queue size is 5)
    if (listen(server_socket, 5) == -1) {
        cerr << "Failed to listen for connections.\n";
        close(server_socket);
        exit(1);
    }

    while (1) {
        // Accept incoming connections
        client_socket = accept(server_socket, NULL, NULL);
        if (client_socket == -1) {
            cerr << "Failed to accept the client.\n";
            continue;
        }

        // Create a new process to handle the client
        pid_t new_pid = fork();

        if (new_pid == 0) {  // Child process
            close(server_socket);  // Child doesn't need the server socket

            // Perform Diffie-Hellman key exchange
            diffie_hellman_key_exchange(client_socket);

            // Handle user registration
            handle_registration(client_socket);

            // Close the client socket
            close(client_socket);
            exit(0);
        } else if (new_pid < 0) {
            cerr << "Fork failed.\n";
        }

        close(client_socket);  // Parent doesn't need the client socket
    }

    // Close the server socket
    close(server_socket);

    return 0;
}


// #include <iostream>
// #include <cstring>
// #include <sys/socket.h>
// #include <sys/types.h>
// #include <netinet/in.h>
// #include <unistd.h>
// #include <openssl/bn.h>       // For Diffie-Hellman
// #include <openssl/sha.h>      // For hashing passwords
// #include <openssl/rand.h>     // For generating salt
// #include <fstream>
// #include <sstream>
// #include <vector>

// using namespace std;

// const int p = 23;  // Prime number (public parameter)
// const int g = 5;   // Primitive root (public parameter)
// BIGNUM *shared_secret = nullptr;  // Shared secret key

// // Generate a random private key (server-side)
// BIGNUM* generate_private_key() {
//     BIGNUM *private_key = BN_new();
//     BN_rand(private_key, 128, 0, 0);  // Generate a random 128-bit private key
//     return private_key;
// }

// // Compute public key (g^private_key % p)
// BIGNUM* compute_public_key(BIGNUM *private_key) {
//     BIGNUM *g_bn = BN_new();
//     BIGNUM *p_bn = BN_new();
//     BIGNUM *public_key = BN_new();
//     BN_CTX *ctx = BN_CTX_new();

//     BN_set_word(g_bn, g);
//     BN_set_word(p_bn, p);

//     // public_key = g^private_key % p
//     BN_mod_exp(public_key, g_bn, private_key, p_bn, ctx);

//     BN_free(g_bn);
//     BN_free(p_bn);
//     BN_CTX_free(ctx);

//     return public_key;
// }

// // Send a public key to the client
// void send_public_key(int client_socket, BIGNUM *public_key) {
//     char *public_key_str = BN_bn2hex(public_key);
//     send(client_socket, public_key_str, strlen(public_key_str), 0);
//     OPENSSL_free(public_key_str);
// }

// // Receive public key from client
// BIGNUM* receive_public_key(int client_socket) {
//     char buf[256];
//     recv(client_socket, buf, sizeof(buf), 0);
//     BIGNUM *client_public_key = BN_new();
//     BN_hex2bn(&client_public_key, buf);
//     return client_public_key;
// }

// // Compute shared secret using client's public key
// BIGNUM* compute_shared_secret(BIGNUM *client_public_key, BIGNUM *private_key) {
//     BIGNUM *p_bn = BN_new();
//     BIGNUM *shared_secret = BN_new();
//     BN_CTX *ctx = BN_CTX_new();

//     BN_set_word(p_bn, p);

//     // shared_secret = client_public_key^private_key % p
//     BN_mod_exp(shared_secret, client_public_key, private_key, p_bn, ctx);

//     BN_free(p_bn);
//     BN_CTX_free(ctx);

//     return shared_secret;
// }

// // Perform Diffie-Hellman Key Exchange (Server-Side)
// void diffie_hellman_key_exchange(int client_socket) {
//     // 1. Generate private key
//     BIGNUM *private_key = generate_private_key();
//     cout << "Server: Private key generated." << endl;

//     // 2. Compute public key (g^private_key % p)
//     BIGNUM *public_key = compute_public_key(private_key);
//     cout << "Server: Public key generated." << endl;

//     // 3. Send public key to the client
//     send_public_key(client_socket, public_key);
//     cout << "Server: Public key sent to client." << endl;

//     // 4. Receive client's public key
//     BIGNUM *client_public_key = receive_public_key(client_socket);
//     cout << "Server: Client's public key received." << endl;

//     // 5. Compute shared secret
//     shared_secret = compute_shared_secret(client_public_key, private_key);
//     cout << "Server: Shared secret computed." << endl;

//     // Cleanup
//     BN_free(private_key);
//     BN_free(public_key);
//     BN_free(client_public_key);
// }

// // Helper function to hash a password using SHA-256 with a salt
// string hash_password_with_salt(const string &password, const string &salt) {
//     string combined = password + salt;  // Combine password and salt

//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     SHA256((unsigned char*)combined.c_str(), combined.length(), hash);

//     stringstream ss;
//     for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
//         ss << hex << (int)hash[i];
//     }

//     return ss.str();
// }

// // Helper function to generate a random salt (32-bit length)
// string generate_salt() {
//     unsigned char salt[4];  // 32-bit (4 bytes) salt
//     RAND_bytes(salt, sizeof(salt));

//     stringstream ss;
//     for (int i = 0; i < sizeof(salt); ++i) {
//         ss << hex << (int)salt[i];
//     }

//     return ss.str();
// }

// // Check if a username or email is unique in creds.txt
// bool is_unique(const string &username, const string &email) {
//     ifstream file("creds.txt");
//     string line;
//     while (getline(file, line)) {
//         istringstream iss(line);
//         string stored_email, stored_username, stored_password, stored_salt;
//         iss >> stored_email >> stored_username >> stored_password >> stored_salt;

//         if (stored_username == username || stored_email == email) {
//             return false;  // Username or email already exists
//         }
//     }
//     return true;  // Unique
// }

// // Save new user credentials to creds.txt
// void save_credentials(const string &email, const string &username, const string &hashed_password, const string &salt) {
//     ofstream file("creds.txt", ios::app);
//     file << "email: " << email << ", username: " << username 
//          << ", password: " << hashed_password << ", salt: " << salt << endl;
// }

// // Handle user registration process
// void handle_registration(int client_socket) {
//     char buf[256];

//     // Receive encrypted registration info (email, username, password) from the client
//     recv(client_socket, buf, sizeof(buf), 0);

//     // Decrypt the received information using shared_secret (For now, assume it's plaintext for simplicity)
//     string registration_info(buf);
//     istringstream iss(registration_info);
//     string email, username, password;
//     iss >> email >> username >> password;

//     cout << "Server: Received registration info - Email: " << email << ", Username: " << username << endl;

//     // Check if the username or email is unique
//     if (!is_unique(username, email)) {
//         string error_message = "Username or email already exists. Please choose another one.";
//         send(client_socket, error_message.c_str(), error_message.length(), 0);
//         return;
//     }

//     // Generate a random salt
//     string salt = generate_salt();
//     cout << "Server: Generated salt: " << salt << endl;

//     // Hash the password with the salt
//     string hashed_password = hash_password_with_salt(password, salt);

//     // Save the credentials to creds.txt
//     save_credentials(email, username, hashed_password, salt);

//     // Send success message to the client
//     string success_message = "Registration successful!";
//     send(client_socket, success_message.c_str(), success_message.length(), 0);

// }
// // Handle user login process
// void handle_login(int client_socket) {
//     char buf[256];

//     // Receive encrypted login info (username, password) from the client
//     recv(client_socket, buf, sizeof(buf), 0);

//     // Decrypt the received information using shared_secret (For now, assume it's plaintext for simplicity)
//     string login_info(buf);
//     istringstream iss(login_info);
//     string username, password;
//     iss >> username >> password;

//     cout << "Server: Received login info - Username: " << username << endl;

//     // Retrieve stored credentials from creds.txt
//     ifstream file("creds.txt");
//     string line, stored_email, stored_username, stored_password, stored_salt;
//     bool user_found = false;

//     while (getline(file, line)) {
//         istringstream iss(line);
//         iss >> stored_email >> stored_username >> stored_password >> stored_salt;

//         if (stored_username == username) {
//             user_found = true;
//             break;
//         }
//     }

//     if (!user_found) {
//         string error_message = "Username not found.";
//         send(client_socket, error_message.c_str(), error_message.length(), 0);
//         return;
//     }

//     // Hash the entered password with the stored salt
//     string hashed_password = hash_password_with_salt(password, stored_salt);

//     // Compare the hashed password with the stored hashed password
//     if (hashed_password == stored_password) {
//         string success_message = "Login successful! Access granted to the chat system.";
//         send(client_socket, success_message.c_str(), success_message.length(), 0);
//     } else {
//         string error_message = "Incorrect password. Access denied.";
//         send(client_socket, error_message.c_str(), error_message.length(), 0);
//     }
// }


// int main() {
//     char buf[256];
//     int server_socket, client_socket;
//     struct sockaddr_in server_address;

//     cout << "\n\t>>>>>>>>>> XYZ University Chat Server <<<<<<<<<<\n\n";

//     // Create the server socket
//     server_socket = socket(AF_INET, SOCK_STREAM, 0);
//     if (server_socket == -1) {
//         cerr << "Failed to create socket.\n";
//         exit(1);
//     }

//     // Define the server address
//     server_address.sin_family = AF_INET;
//     server_address.sin_port = htons(8002);
//     server_address.sin_addr.s_addr = INADDR_ANY;

//     // Bind the socket to the specified IP and port
//     if (bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address)) == -1) {
//         cerr << "Failed to bind to the port.\n";
//         close(server_socket);
//         exit(1);
//     }

//     // Listen for incoming connections (queue size is 5)
//     if (listen(server_socket, 5) == -1) {
//         cerr << "Failed to listen for connections.\n";
//         close(server_socket);
//         exit(1);
//     }

//     while (1) {
//         // Accept incoming connections
//         client_socket = accept(server_socket, NULL, NULL);
//         if (client_socket == -1) {
//             cerr << "Failed to accept the client.\n";
//             continue;
//         }

//         // Create a new process to handle the client
//         pid_t new_pid = fork();

//         if (new_pid == 0) {  // Child process
//             close(server_socket);  // Child doesn't need the server socket

//             // Perform Diffie-Hellman key exchange
//             diffie_hellman_key_exchange(client_socket);

//             // Handle user registration
//             handle_registration(client_socket);

//             // Close the client socket
//             close(client_socket);
//             exit(0);
//         } else if (new_pid < 0) {
//             cerr << "Fork failed.\n";
//         }

//         close(client_socket);  // Parent doesn't need the client socket
//     }

//     // Close the server socket
//     close(server_socket);

//     return 0;
// }
