#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <set>
#include <thread>
#include <fstream>
#include <unordered_set>



// Function to read addresses from a file and return them as a sorted set
std::unordered_set<std::string> loadAddresses(const std::string& filename) {
    std::unordered_set<std::string> addresses;
    std::ifstream file(filename);
    std::string address;

    while (std::getline(file, address)) {
        addresses.insert(address);
    }

    return addresses;
}

// Helper function to convert bytes to a hex string
std::string toHexString(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Helper function to perform SHA256 hashing
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    std::vector<unsigned char> hash(EVP_MD_size(EVP_sha256()));
    unsigned int lengthOfHash = 0;

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &lengthOfHash);

    hash.resize(lengthOfHash);
    EVP_MD_CTX_free(ctx);

    return hash;
}

// Helper function to perform RIPEMD160 hashing
std::vector<unsigned char> ripemd160(const std::vector<unsigned char>& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    std::vector<unsigned char> hash(EVP_MD_size(EVP_ripemd160()));
    unsigned int lengthOfHash = 0;

    EVP_DigestInit_ex(ctx, EVP_ripemd160(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &lengthOfHash);

    hash.resize(lengthOfHash);
    EVP_MD_CTX_free(ctx);

    return hash;
}

// Helper function to perform Base58 encoding
std::string base58Encode(const std::vector<unsigned char>& data) {
    static const char* const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string result;
    BIGNUM* bn = BN_new();
    BN_bin2bn(data.data(), data.size(), bn);

    // Convert to Base58
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* base = BN_new();
    BN_set_word(base, 58);
    BIGNUM* rem = BN_new();
    while (!BN_is_zero(bn)) {
        BN_div(bn, rem, bn, base, ctx);
        unsigned long c = BN_get_word(rem);
        result.push_back(alphabet[c]);
    }

    // Add '1' characters for each leading 0 byte
    for (auto it = data.begin(); it != data.end() && *it == 0; ++it) {
        result.push_back('1');
    }

    std::reverse(result.begin(), result.end());

    BN_CTX_free(ctx);
    BN_free(bn);
    BN_free(base);
    BN_free(rem);

    return result;
}

// Function to generate an uncompressed public key from a private key
std::vector<unsigned char> getUncompressedPublicKey(const std::string& privateKeyHex) {
    std::vector<unsigned char> uncompressedPublicKey;
    BIGNUM* prv = nullptr;
    BN_hex2bn(&prv, privateKeyHex.c_str());
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_private_key(key, prv);
    const EC_GROUP* group = EC_KEY_get0_group(key);
    EC_POINT* pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, prv, nullptr, nullptr, nullptr);

    // Serialize the uncompressed public key
    unsigned char* pubBytes = nullptr;
    size_t pubLen = EC_POINT_point2buf(group, pub, POINT_CONVERSION_UNCOMPRESSED, &pubBytes, nullptr);
    uncompressedPublicKey.assign(pubBytes, pubBytes + pubLen);
    OPENSSL_free(pubBytes);

    // Free resources
    EC_POINT_free(pub);
    BN_free(prv);
    EC_KEY_free(key);

    return uncompressedPublicKey;
}

// Function to generate a compressed public key from a private key
std::vector<unsigned char> getCompressedPublicKey(const std::string& privateKeyHex) {
    std::vector<unsigned char> compressedPublicKey;
    BIGNUM* prv = nullptr;
    BN_hex2bn(&prv, privateKeyHex.c_str());
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_private_key(key, prv);
    const EC_GROUP* group = EC_KEY_get0_group(key);
    EC_POINT* pub = EC_POINT_new(group);
    EC_POINT_mul(group, pub, prv, nullptr, nullptr, nullptr);

    // Serialize the compressed public key
    unsigned char* pubBytes = nullptr;
    size_t pubLen = EC_POINT_point2buf(group, pub, POINT_CONVERSION_COMPRESSED, &pubBytes, nullptr);
    compressedPublicKey.assign(pubBytes, pubBytes + pubLen);
    OPENSSL_free(pubBytes);

    // Free resources
    EC_POINT_free(pub);
    BN_free(prv);
    EC_KEY_free(key);

    return compressedPublicKey;
}

std::string generateBitcoinAddress(const std::vector<unsigned char>& publicKey, bool compressed) {
    // return "jobi";
    std::vector<unsigned char> publicKeyToHash;

    if (compressed) {
        // Compressed public key format
        publicKeyToHash.push_back(publicKey[64] & 1 ? 0x03 : 0x02);
        publicKeyToHash.insert(publicKeyToHash.end(), publicKey.begin() + 1, publicKey.begin() + 33);
    } else {
        // Uncompressed public key format
        publicKeyToHash = publicKey;
    }

    // Perform SHA-256 hashing on the public key
    std::vector<unsigned char> sha256Hash = sha256(publicKeyToHash);

    // Perform RIPEMD-160 hashing on the result of SHA-256
    std::vector<unsigned char> ripemd160Hash = ripemd160(sha256Hash);

    // Prepend version byte (0x00 for Main Network)
    std::vector<unsigned char> versionAndPayload = {0x00};
    versionAndPayload.insert(versionAndPayload.end(), ripemd160Hash.begin(), ripemd160Hash.end());

    // Perform SHA-256 hash on the extended RIPEMD-160 result
    std::vector<unsigned char> hash1 = sha256(versionAndPayload);

    // Perform SHA-256 hash on the result of the previous SHA-256 hash
    std::vector<unsigned char> hash2 = sha256(hash1);

    // Take the first 4 bytes of the second SHA-256 hash for the checksum
    std::vector<unsigned char> checksum(hash2.begin(), hash2.begin() + 4);

    // Add the 4 checksum bytes to the extended RIPEMD-160 hash to form the full 25-byte binary Bitcoin Address
    std::vector<unsigned char> binaryAddress = versionAndPayload;
    binaryAddress.insert(binaryAddress.end(), checksum.begin(), checksum.end());

    // Convert the result from a byte string into a base58 string using Base58Check encoding
    std::string btcAddress = base58Encode(binaryAddress);

    return btcAddress;
}

int makeAttempt(std::unordered_set<std::string> sortedAddresses) {
    // Generate a new random private key for each iteration
    unsigned char rand_data[32];
    if (RAND_bytes(rand_data, sizeof(rand_data)) != 1) {
        std::cerr << "Error generating random data." << std::endl;
        return 1;
    }

    // Convert the private key to a hexadecimal string
    std::vector<unsigned char> rand_data_vec(rand_data, rand_data + sizeof(rand_data));
    std::string privateKeyHex = toHexString(rand_data_vec);

        // Generate both uncompressed and compressed public keys
    std::vector<unsigned char> uncompressedPublicKey = getUncompressedPublicKey(privateKeyHex);
    std::vector<unsigned char> compressedPublicKey = getCompressedPublicKey(privateKeyHex);

    // Generate the Bitcoin address from the uncompressed public key
    std::string btcAddressUncompressed = generateBitcoinAddress(uncompressedPublicKey, false);

    // Check if the generated uncompressed address is in the sorted list
    if (sortedAddresses.find(btcAddressUncompressed) != sortedAddresses.end()) {
        std::cout << "Match found with uncompressed address!" << std::endl;
        std::cout << "Bitcoin Address: " << btcAddressUncompressed << std::endl;
        std::cout << "Public Key: " << toHexString(uncompressedPublicKey) << std::endl;
        std::cout << "Private Key: " << privateKeyHex << std::endl;
    }

    // Generate the Bitcoin address from the compressed public key
    std::string btcAddressCompressed = generateBitcoinAddress(compressedPublicKey, true);

    // Check if the generated compressed address is in the sorted list
    if (sortedAddresses.find(btcAddressCompressed) != sortedAddresses.end()) {
        std::cout << "Match found with compressed address!" << std::endl;
        std::cout << "Bitcoin Address: " << btcAddressCompressed << std::endl;
        std::cout << "Public Key: " << toHexString(std::vector<unsigned char>(compressedPublicKey.begin(), compressedPublicKey.begin() + 33)) << std::endl;
        std::cout << "Private Key: " << privateKeyHex << std::endl;
    }

    return 0;
}

int main() {
    auto sortedAddresses = loadAddresses("addresses_full.txt");
    auto start_time = std::chrono::steady_clock::now();
    auto status_time = start_time;

    while (true) {
        makeAttempt(sortedAddresses);

        // Sleep for a short time to prevent 100% CPU utilization (optional)
        //std::this_thread::sleep_for(std::chrono::nanoseconds(1));
    }

    return 0;
}