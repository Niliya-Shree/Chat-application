/* Chat Application (C++, Socket Programming) */

#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <openssl/aes.h>
#include <sqlite3.h>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1024

std::mutex mtx;

// AES Encryption function
void AES_encrypt_decrypt(const unsigned char *input, unsigned char *output, const AES_KEY *key, bool encrypt) {
    if (encrypt) {
        AES_encrypt(input, output, key);
    } else {
        AES_decrypt(input, output, key);
    }
}

// SQLite Database setup for authentication
bool initializeDatabase(sqlite3 *&db) {
    if (sqlite3_open("chat_users.db", &db) != SQLITE_OK) {
        std::cerr << "Database error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    std::string sql = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);";
    char *errMsg;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL Error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

// Server handling function
void handleClient(int clientSocket, AES_KEY &aesKey) {
    char buffer[BUFFER_SIZE];
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (bytesReceived <= 0) {
            std::cout << "Client disconnected." << std::endl;
            close(clientSocket);
            return;
        }
        unsigned char decrypted[BUFFER_SIZE];
        AES_encrypt_decrypt((unsigned char *)buffer, decrypted, &aesKey, false);
        std::cout << "Client: " << decrypted << std::endl;
        std::string reply = "Server: Message Received";
        unsigned char encrypted[BUFFER_SIZE];
        AES_encrypt_decrypt((unsigned char *)reply.c_str(), encrypted, &aesKey, true);
        send(clientSocket, encrypted, reply.length(), 0);
    }
}

// Main Server function
void startServer() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    bind(serverSocket, (sockaddr *)&serverAddr, sizeof(serverAddr));
    listen(serverSocket, 5);
    std::cout << "Server is listening on port " << PORT << std::endl;
    AES_KEY aesKey;
    AES_set_encrypt_key((unsigned char *)"myencryptionkey", 128, &aesKey);

    while (true) {
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        std::cout << "New client connected." << std::endl;
        std::thread(handleClient, clientSocket, std::ref(aesKey)).detach();
    }
    close(serverSocket);
}

// Main Client function
void startClient() {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    connect(clientSocket, (sockaddr *)&serverAddr, sizeof(serverAddr));
    std::cout << "Connected to server." << std::endl;
    AES_KEY aesKey;
    AES_set_encrypt_key((unsigned char *)"myencryptionkey", 128, &aesKey);
    
    while (true) {
        std::string message;
        std::getline(std::cin, message);
        unsigned char encrypted[BUFFER_SIZE];
        AES_encrypt_decrypt((unsigned char *)message.c_str(), encrypted, &aesKey, true);
        send(clientSocket, encrypted, message.length(), 0);
        char buffer[BUFFER_SIZE];
        recv(clientSocket, buffer, BUFFER_SIZE, 0);
        unsigned char decrypted[BUFFER_SIZE];
        AES_encrypt_decrypt((unsigned char *)buffer, decrypted, &aesKey, false);
        std::cout << decrypted << std::endl;
    }
    close(clientSocket);
}

int main() {
    int choice;
    std::cout << "1. Start Server\n2. Start Client\nEnter choice: ";
    std::cin >> choice;
    std::cin.ignore();
    
    if (choice == 1) {
        startServer();
    } else if (choice == 2) {
        startClient();
    }
    return 0;
}
