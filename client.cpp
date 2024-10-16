#include <iostream>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>  // Include this to use inet_addr()
#include <regex>
#include <openssl/evp.h>
#include <openssl/aes.h>

using namespace std;

int sock;
const unsigned char *AES_ENCRYPTION_KEY = (unsigned char *)"0123456789abcdef"; // Pre-shared key (16 bytes for AES-128)
const unsigned char *IV = (unsigned char *)"1234567890123456";                  // Initialization Vector (16 bytes)

void create_socket() {
    // create the socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        cerr << "Error creating socket." << endl;
        exit(1);
    }

    // setup an address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8004);

    // Use localhost or specify a valid IP address for the server
    if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0) {
        cerr << "Invalid address or Address not supported." << endl;
        exit(1);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        cerr << "Connection to server failed." << endl;
        exit(1);
    }
}

bool is_valid_email(const string& email) {
    // Simple regex for validating email
    const regex pattern(R"((\w+)(\.{1}\w+)?@(\w+)\.(\w+))");
    return regex_match(email, pattern);
}

void handle_errors() {
    cerr << "An error occurred during encryption." << endl;
    exit(1);
}

// AES-128 CBC encryption function
int aes_encrypt(const string &plaintext, unsigned char *ciphertext, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    // Initialize encryption operation (AES-128 CBC)
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handle_errors();

    // Provide the plaintext to be encrypted
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext.c_str(), plaintext.length()))
        handle_errors();
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handle_errors();
    ciphertext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void encrypt_and_send(const string &email, const string &username, const string &password) {
    unsigned char encrypted_email[128], encrypted_username[128], encrypted_password[128];
    int email_len, username_len, password_len;

    // Encrypt the email
    email_len = aes_encrypt(email, encrypted_email, AES_ENCRYPTION_KEY, IV);
    // Encrypt the username
    username_len = aes_encrypt(username, encrypted_username, AES_ENCRYPTION_KEY, IV);
    // Encrypt the password
    password_len = aes_encrypt(password, encrypted_password, AES_ENCRYPTION_KEY, IV);

    // Send encrypted data to server (for simplicity, sending them separately)
    send(sock, encrypted_email, email_len, 0);
    send(sock, encrypted_username, username_len, 0);
    send(sock, encrypted_password, password_len, 0);

    cout << "\nEncrypted user data sent to the server.\n";
}

void register_user() {
    string email, username, password;

    // Prompt for valid email
    do {
        cout << "Enter a valid email address: ";
        getline(cin, email);
        if (!is_valid_email(email)) {
            cout << "Invalid email format. Please try again.\n";
        }
    } while (!is_valid_email(email));

    // Prompt for unique username
    cout << "Enter a unique username: ";
    getline(cin, username);

    // Prompt for password
    cout << "Enter a password: ";
    getline(cin, password);

    cout << "\nEncrypting user data...\n";
    encrypt_and_send(email, username, password);
}
void diffie_hellman_key_exchange(BIGNUM*& shared_secret) {
    // Set up prime (p) and generator (g)
    BIGNUM *p = BN_new();
    BIGNUM *g = BN_new();
    BN_set_word(p, 23);  // Choose a large prime (example: 23)
    BN_set_word(g, 5);   // Primitive root (example: 5)

    // Generate private key
    BIGNUM *private_key = BN_new();
    BN_rand(private_key, 128, 0, 0);  // Generate a random 128-bit private key

    // Compute public key
    BIGNUM *public_key = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(public_key, g, private_key, p, ctx); // public_key = g^private_key % p

    // Send public key to server
    char *public_key_str = BN_bn2hex(public_key);
    send(sock, public_key_str, strlen(public_key_str), 0);
    OPENSSL_free(public_key_str);

    // Receive server's public key
    char server_public_key_str[256];
    recv(sock, server_public_key_str, sizeof(server_public_key_str), 0);
    BIGNUM *server_public_key = BN_new();
    BN_hex2bn(&server_public_key, server_public_key_str);

    // Compute shared secret
    shared_secret = BN_new();
    BN_mod_exp(shared_secret, server_public_key, private_key, p, ctx); // shared_secret = server_public_key^private_key % p

    // Cleanup
    BN_CTX_free(ctx);
    BN_free(p);
    BN_free(g);
    BN_free(private_key);
    BN_free(public_key);
    BN_free(server_public_key);
}

void login_user() {
    string username, password;
    BIGNUM *shared_secret = nullptr;

    // Prompt for username and password
    cout << "Enter your username: ";
    getline(cin, username);
    cout << "Enter your password: ";
    getline(cin, password);

    // Perform Diffie-Hellman key exchange for login
    diffie_hellman_key_exchange(shared_secret);
    cout << "\nDiffie-Hellman key exchange completed.\n";

    // Convert shared secret to encryption key (use first 16 bytes of shared secret for AES-128)
    unsigned char key[16];
    BN_bn2bin(shared_secret, key);

    // Encrypt and send login credentials
    unsigned char encrypted_username[128], encrypted_password[128];
    int username_len, password_len;

    username_len = aes_encrypt(username, encrypted_username, key, IV);
    password_len = aes_encrypt(password, encrypted_password, key, IV);

    send(sock, encrypted_username, username_len, 0);
    send(sock, encrypted_password, password_len, 0);

    cout << "\nEncrypted login data sent to the server.\n";

    // Cleanup
    BN_free(shared_secret);
}

void show_menu() {
    cout << "\n\t>>>>>>>>>> XYZ University Chat Client <<<<<<<<<<\n\n";
    cout << "1. Register\n";
    cout << "2. Login\n";
    cout << "3. Exit\n";
    cout << "Enter your choice: ";
}

int main() {
    char buf[256];
    int choice;

    // Create socket and connect to the server
    create_socket();

    while (true) {
        // Display menu
        show_menu();
        cin >> choice;
        cin.ignore(); // to clear the input buffer

        if (choice == 1) {
            // User Registration
            register_user();
        } else if (choice == 2) {
            // Login functionality can be implemented here
            login_user();
        } else if (choice == 3) {
            cout << "Exiting...\n";
            break;
        } else {
            cout << "Invalid choice. Please try again.\n";
        }

        // Clear buffer and receive response from server
        memset(buf, 0, sizeof(buf));
        recv(sock, buf, sizeof(buf), 0);
        cout << buf << endl;
    }

    // Close the socket after communication
    close(sock);

    return 0;
}





// #include <iostream>
// #include <cstring>
// #include <sys/types.h>
// #include <sys/socket.h>
// #include <unistd.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>  // Include this to use inet_addr()
// #include <regex>
// #include <openssl/evp.h>
// #include <openssl/aes.h>
// #include <openssl/bn.h> // For Diffie-Hellman key exchange
// #include <sstream>

// using namespace std;

// int sock;
// BIGNUM *shared_secret = nullptr;  // Shared secret key

// // Helper constants for AES encryption (could be updated based on Diffie-Hellman)
// const unsigned char *IV = (unsigned char *)"1234567890123456";  // Initialization Vector (16 bytes)

// void create_socket() {
//     // Create the socket
//     sock = socket(AF_INET, SOCK_STREAM, 0);
//     if (sock == -1) {
//         cerr << "Error creating socket." << endl;
//         exit(1);
//     }

//     // Setup server address
//     struct sockaddr_in server_address;
//     server_address.sin_family = AF_INET;
//     server_address.sin_port = htons(8002);

//     // Use localhost or specify a valid IP address for the server
//     if (inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) <= 0) {
//         cerr << "Invalid address or Address not supported." << endl;
//         exit(1);
//     }

//     // Connect to the server
//     if (connect(sock, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
//         cerr << "Connection to server failed." << endl;
//         exit(1);
//     }
// }

// // Function to handle errors
// void handle_errors() {
//     cerr << "An error occurred during encryption." << endl;
//     exit(1);
// }

// // Helper function for Diffie-Hellman key exchange (generate private key)
// BIGNUM* generate_private_key() {
//     BIGNUM *private_key = BN_new();
//     BN_rand(private_key, 128, 0, 0);  // Generate a random 128-bit private key
//     return private_key;
// }

// // Function to compute public key (g^private_key % p)
// BIGNUM* compute_public_key(BIGNUM *private_key, BIGNUM *g, BIGNUM *p) {
//     BIGNUM *public_key = BN_new();
//     BN_CTX *ctx = BN_CTX_new();
//     BN_mod_exp(public_key, g, private_key, p, ctx); // public_key = g^private_key % p
//     BN_CTX_free(ctx);
//     return public_key;
// }

// // Diffie-Hellman key exchange
// void diffie_hellman_key_exchange() {
//     // Set up prime (p) and generator (g)
//     BIGNUM *p = BN_new();
//     BIGNUM *g = BN_new();
//     BN_set_word(p, 23);  // Choose a large prime (example: 23)
//     BN_set_word(g, 5);   // Primitive root (example: 5)

//     // Generate private key
//     BIGNUM *private_key = generate_private_key();
    
//     // Compute public key
//     BIGNUM *public_key = compute_public_key(private_key, g, p);

//     // Send public key to server
//     char *public_key_str = BN_bn2hex(public_key);
//     send(sock, public_key_str, strlen(public_key_str), 0);
//     OPENSSL_free(public_key_str);

//     // Receive server's public key
//     char server_public_key_str[256];
//     recv(sock, server_public_key_str, sizeof(server_public_key_str), 0);
//     BIGNUM *server_public_key = BN_new();
//     BN_hex2bn(&server_public_key, server_public_key_str);

//     // Compute shared secret
//     shared_secret = BN_new();
//     BN_CTX *ctx = BN_CTX_new();
//     BN_mod_exp(shared_secret, server_public_key, private_key, p, ctx); // shared_secret = server_public_key^private_key % p
//     BN_CTX_free(ctx);

//     // Cleanup
//     BN_free(p);
//     BN_free(g);
//     BN_free(private_key);
//     BN_free(public_key);
//     BN_free(server_public_key);
// }

// // AES-128 CBC encryption function
// int aes_encrypt(const string &plaintext, unsigned char *ciphertext, const unsigned char *key, const unsigned char *iv) {
//     EVP_CIPHER_CTX *ctx;
//     int len;
//     int ciphertext_len;

//     // Create and initialize the context
//     if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

//     // Initialize encryption operation (AES-128 CBC)
//     if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
//         handle_errors();

//     // Provide the plaintext to be encrypted
//     if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext.c_str(), plaintext.length()))
//         handle_errors();
//     ciphertext_len = len;

//     // Finalize encryption
//     if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handle_errors();
//     ciphertext_len += len;

//     // Clean up
//     EVP_CIPHER_CTX_free(ctx);

//     return ciphertext_len;
// }

// bool is_valid_email(const string &email) {
//     // Simple regex for validating email
//     const regex pattern(R"((\w+)(\.{1}\w+)?@(\w+)\.(\w+))");
//     return regex_match(email, pattern);
// }

// // Function to encrypt and send the registration details (email, username, password)
// void encrypt_and_send(const string &email, const string &username, const string &password) {
//     unsigned char encrypted_email[128], encrypted_username[128], encrypted_password[128];
//     int email_len, username_len, password_len;

//     // Convert shared secret to encryption key (use first 16 bytes of shared secret for AES-128)
//     unsigned char key[16];
//     BN_bn2bin(shared_secret, key);

//     // Encrypt the email
//     email_len = aes_encrypt(email, encrypted_email, key, IV);
//     // Encrypt the username
//     username_len = aes_encrypt(username, encrypted_username, key, IV);
//     // Encrypt the password
//     password_len = aes_encrypt(password, encrypted_password, key, IV);

//     // Send encrypted data to server
//     send(sock, encrypted_email, email_len, 0);
//     send(sock, encrypted_username, username_len, 0);
//     send(sock, encrypted_password, password_len, 0);

//     cout << "\nEncrypted user data sent to the server.\n";
// }

// // Function for user registration
// void register_user() {
//     string email, username, password;

//     // Prompt for valid email
//     do {
//         cout << "Enter a valid email address: ";
//         getline(cin, email);
//         if (!is_valid_email(email)) {
//             cout << "Invalid email format. Please try again.\n";
//         }
//     } while (!is_valid_email(email));

//     // Prompt for unique username
//     cout << "Enter a unique username: ";
//     getline(cin, username);

//     // Prompt for password
//     cout << "Enter a password: ";
//     getline(cin, password);

//     // Perform Diffie-Hellman key exchange
//     diffie_hellman_key_exchange();
//     cout << "\nDiffie-Hellman key exchange completed.\n";

//     // Encrypt and send user data
//     cout << "\nEncrypting user data...\n";
//     encrypt_and_send(email, username, password);
// }

// // Function to display the menu
// void show_menu() {
//     cout << "\n\t>>>>>>>>>> XYZ University Chat Client <<<<<<<<<<\n\n";
//     cout << "1. Register\n";
//     cout << "2. Login\n";
//     cout << "3. Exit\n";
//     cout << "Enter your choice: ";
// }

// // Function for login (to be implemented similarly to registration)
// void login_user() {
//     string username, password;

//     // Prompt for username and password
//     cout << "Enter your username: ";
//     getline(cin, username);
//     cout << "Enter your password: ";
//     getline(cin, password);

//     // Perform Diffie-Hellman key exchange for login
//     diffie_hellman_key_exchange();
//     cout << "\nDiffie-Hellman key exchange completed.\n";

//     // Encrypt and send login credentials
//     cout << "\nEncrypting login data...\n";
//     encrypt_and_send(username, "", password);  // Only sending username and password for login
// }

// int main() {
//     char buf[256];
//     int choice;

//     // Create socket and connect to the server
//     create_socket();

//     while (true) {
//         // Display menu
//         show_menu();
//         cin >> choice;
//         cin.ignore(); // to clear the input buffer

//         if (choice == 1) {
//             // User Registration
//             register_user();
//         } else if (choice == 2) {
//             // User Login
//             login_user();
//         } else if (choice == 3) {
//             cout << "Exiting...\n";
//             break;
//         } else {
//             cout << "Invalid choice. Please try again.\n";
//         }

//         // Clear buffer and receive response from server
//         memset(buf, 0, sizeof(buf));
//         recv(sock, buf, sizeof(buf), 0);
//         cout << buf << endl;
//     }

//     // Close the socket after communication
//     close(sock);

//     return 0;
// }


