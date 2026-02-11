
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <map>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

namespace fs = std::filesystem;

// Enum for hash algorithm types
enum class HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
    SHA512
};

// Structure to hold hash results
struct HashResult {
    std::string filename;
    std::string hash;
    std::string algorithm;
    bool success;
    std::string error;
};

// Class encapsulating file integrity checking functionality
class FileIntegrityChecker {
private:
    bool verbose;
    HashAlgorithm algorithm;

    // Get the OpenSSL EVP message digest based on algorithm
    const EVP_MD* getMessageDigest() const {
        switch (algorithm) {
            case HashAlgorithm::MD5:
                return EVP_md5();
            case HashAlgorithm::SHA1:
                return EVP_sha1();
            case HashAlgorithm::SHA256:
                return EVP_sha256();
            case HashAlgorithm::SHA512:
                return EVP_sha512();
            default:
                return EVP_sha256();
        }
    }

    // Get algorithm name as string
    std::string getAlgorithmName() const {
        switch (algorithm) {
            case HashAlgorithm::MD5: return "MD5";
            case HashAlgorithm::SHA1: return "SHA-1";
            case HashAlgorithm::SHA256: return "SHA-256";
            case HashAlgorithm::SHA512: return "SHA-512";
            default: return "SHA-256";
        }
    }

public:
    // Constructor with verbose mode and algorithm selection
    FileIntegrityChecker(bool verbose = false, HashAlgorithm algo = HashAlgorithm::SHA256)
        : verbose(verbose), algorithm(algo) {}

    // Calculate hash of a file using modern OpenSSL EVP API
    HashResult calculateHash(const std::string& filepath) {
        HashResult result;
        result.filename = filepath;
        result.algorithm = getAlgorithmName();
        result.success = false;

        if (verbose) {
            std::cout << "Processing: " << filepath << std::endl;
        }

        // Check if file exists
        if (!fs::exists(filepath)) {
            result.error = "File does not exist";
            return result;
        }

        // Check if it's a regular file
        if (!fs::is_regular_file(filepath)) {
            result.error = "Not a regular file";
            return result;
        }

        // Open file in binary mode
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            result.error = "Cannot open file";
            return result;
        }

        // Initialize EVP context
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            result.error = "Failed to create EVP context";
            return result;
        }

        // Initialize digest
        if (EVP_DigestInit_ex(ctx, getMessageDigest(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            result.error = "Failed to initialize digest";
            return result;
        }

        // Read file and update digest
        char buffer[8192];
        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
            if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
                EVP_MD_CTX_free(ctx);
                result.error = "Failed to update digest";
                return result;
            }
        }

        // Finalize digest
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len = 0;
        if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            result.error = "Failed to finalize digest";
            return result;
        }

        EVP_MD_CTX_free(ctx);

        // Convert hash to hex string
        std::stringstream ss;
        for (unsigned int i = 0; i < hash_len; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }

        result.hash = ss.str();
        result.success = true;
        return result;
    }

    // Process multiple files
    std::vector<HashResult> processFiles(const std::vector<std::string>& filepaths) {
        std::vector<HashResult> results;
        for (const auto& filepath : filepaths) {
            results.push_back(calculateHash(filepath));
        }
        return results;
    }

    // Scan directory and calculate hashes for all files
    std::vector<HashResult> scanDirectory(const std::string& dirpath, bool recursive = false) {
        std::vector<HashResult> results;

        if (!fs::exists(dirpath) || !fs::is_directory(dirpath)) {
            HashResult error;
            error.filename = dirpath;
            error.success = false;
            error.error = "Not a valid directory";
            results.push_back(error);
            return results;
        }

        if (verbose) {
            std::cout << "Scanning directory: " << dirpath << std::endl;
        }

        try {
            if (recursive) {
                for (const auto& entry : fs::recursive_directory_iterator(dirpath)) {
                    if (entry.is_regular_file()) {
                        results.push_back(calculateHash(entry.path().string()));
                    }
                }
            } else {
                for (const auto& entry : fs::directory_iterator(dirpath)) {
                    if (entry.is_regular_file()) {
                        results.push_back(calculateHash(entry.path().string()));
                    }
                }
            }
        } catch (const fs::filesystem_error& e) {
            HashResult error;
            error.filename = dirpath;
            error.success = false;
            error.error = std::string("Filesystem error: ") + e.what();
            results.push_back(error);
        }

        return results;
    }

    // Verify file hash against expected value
    bool verifyHash(const std::string& filepath, const std::string& expectedHash) {
        HashResult result = calculateHash(filepath);
        if (!result.success) {
            if (verbose) {
                std::cerr << "Error calculating hash: " << result.error << std::endl;
            }
            return false;
        }

        // Case-insensitive comparison
        std::string actualHash = result.hash;
        std::string expected = expectedHash;
        std::transform(actualHash.begin(), actualHash.end(), actualHash.begin(), ::tolower);
        std::transform(expected.begin(), expected.end(), expected.begin(), ::tolower);

        return actualHash == expected;
    }

    // Store hashes to a file (database)
    bool saveHashesToFile(const std::vector<HashResult>& results, const std::string& outputFile) {
        std::ofstream outfile(outputFile);
        if (!outfile) {
            return false;
        }

        for (const auto& result : results) {
            if (result.success) {
                outfile << result.algorithm << ":" << result.hash << ":" << result.filename << std::endl;
            }
        }

        return true;
    }

    // Load hashes from file and verify
    std::map<std::string, bool> verifyFromDatabase(const std::string& databaseFile) {
        std::map<std::string, bool> verificationResults;
        std::ifstream infile(databaseFile);

        if (!infile) {
            if (verbose) {
                std::cerr << "Cannot open database file: " << databaseFile << std::endl;
            }
            return verificationResults;
        }

        std::string line;
        while (std::getline(infile, line)) {
            // Parse line: algorithm:hash:filename
            size_t firstColon = line.find(':');
            size_t secondColon = line.find(':', firstColon + 1);

            if (firstColon == std::string::npos || secondColon == std::string::npos) {
                continue;
            }

            std::string algo = line.substr(0, firstColon);
            std::string expectedHash = line.substr(firstColon + 1, secondColon - firstColon - 1);
            std::string filename = line.substr(secondColon + 1);

            // Verify the file
            bool verified = verifyHash(filename, expectedHash);
            verificationResults[filename] = verified;

            if (verbose) {
                std::cout << filename << ": " << (verified ? "PASS" : "FAIL") << std::endl;
            }
        }

        return verificationResults;
    }
};

// Display help message
void displayHelp(const char* programName) {
    std::cout << "File Integrity Checker - Cybersecurity Tool\n\n";
    std::cout << "Usage: " << programName << " [OPTIONS] [FILES/DIRECTORIES]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help              Display this help message\n";
    std::cout << "  -v, --verbose           Enable verbose output\n";
    std::cout << "  -a, --algorithm <algo>  Hash algorithm: md5, sha1, sha256 (default), sha512\n";
    std::cout << "  -d, --directory <dir>   Scan directory for files\n";
    std::cout << "  -r, --recursive         Scan directories recursively\n";
    std::cout << "  -c, --verify <hash>     Verify file against expected hash\n";
    std::cout << "  -s, --save <file>       Save hash results to file\n";
    std::cout << "  -l, --load <file>       Load and verify hashes from database file\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << programName << " file.txt                    # Calculate SHA-256 hash\n";
    std::cout << "  " << programName << " -a md5 file.txt             # Calculate MD5 hash\n";
    std::cout << "  " << programName << " file1.txt file2.txt         # Hash multiple files\n";
    std::cout << "  " << programName << " -d /path/to/dir             # Hash all files in directory\n";
    std::cout << "  " << programName << " -d /path/to/dir -r          # Hash all files recursively\n";
    std::cout << "  " << programName << " -c <hash> file.txt          # Verify file hash\n";
    std::cout << "  " << programName << " -s hashes.db file.txt       # Save hash to database\n";
    std::cout << "  " << programName << " -l hashes.db                # Verify files from database\n";
}

int main(int argc, char** argv) {
    // Parse command line arguments
    bool verbose = false;
    bool recursive = false;
    HashAlgorithm algorithm = HashAlgorithm::SHA256;
    std::string verifyHash;
    std::string saveFile;
    std::string loadFile;
    std::vector<std::string> files;
    std::vector<std::string> directories;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            displayHelp(argv[0]);
            return 0;
        } else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        } else if (arg == "-r" || arg == "--recursive") {
            recursive = true;
        } else if (arg == "-a" || arg == "--algorithm") {
            if (i + 1 < argc) {
                std::string algo = argv[++i];
                std::transform(algo.begin(), algo.end(), algo.begin(), ::tolower);
                if (algo == "md5") {
                    algorithm = HashAlgorithm::MD5;
                } else if (algo == "sha1") {
                    algorithm = HashAlgorithm::SHA1;
                } else if (algo == "sha256") {
                    algorithm = HashAlgorithm::SHA256;
                } else if (algo == "sha512") {
                    algorithm = HashAlgorithm::SHA512;
                } else {
                    std::cerr << "Unknown algorithm: " << algo << std::endl;
                    return 1;
                }
            } else {
                std::cerr << "Missing algorithm parameter\n";
                return 1;
            }
        } else if (arg == "-d" || arg == "--directory") {
            if (i + 1 < argc) {
                directories.push_back(argv[++i]);
            } else {
                std::cerr << "Missing directory parameter\n";
                return 1;
            }
        } else if (arg == "-c" || arg == "--verify") {
            if (i + 1 < argc) {
                verifyHash = argv[++i];
            } else {
                std::cerr << "Missing hash parameter\n";
                return 1;
            }
        } else if (arg == "-s" || arg == "--save") {
            if (i + 1 < argc) {
                saveFile = argv[++i];
            } else {
                std::cerr << "Missing output file parameter\n";
                return 1;
            }
        } else if (arg == "-l" || arg == "--load") {
            if (i + 1 < argc) {
                loadFile = argv[++i];
            } else {
                std::cerr << "Missing database file parameter\n";
                return 1;
            }
        } else if (arg[0] != '-') {
            files.push_back(arg);
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            displayHelp(argv[0]);
            return 1;
        }
    }

    // Create checker instance
    FileIntegrityChecker checker(verbose, algorithm);

    // Handle database verification mode
    if (!loadFile.empty()) {
        auto results = checker.verifyFromDatabase(loadFile);
        int passed = 0, failed = 0;
        for (const auto& [filename, verified] : results) {
            if (!verbose) {
                std::cout << filename << ": " << (verified ? "PASS" : "FAIL") << std::endl;
            }
            if (verified) passed++;
            else failed++;
        }
        std::cout << "\nVerification Results: " << passed << " passed, " << failed << " failed\n";
        return (failed > 0) ? 1 : 0;
    }

    // Handle verification mode
    if (!verifyHash.empty()) {
        if (files.empty()) {
            std::cerr << "No file specified for verification\n";
            return 1;
        }
        bool verified = checker.verifyHash(files[0], verifyHash);
        std::cout << files[0] << ": " << (verified ? "VERIFIED" : "MISMATCH") << std::endl;
        return verified ? 0 : 1;
    }

    // Collect results
    std::vector<HashResult> results;

    // Process directories
    for (const auto& dir : directories) {
        auto dirResults = checker.scanDirectory(dir, recursive);
        results.insert(results.end(), dirResults.begin(), dirResults.end());
    }

    // Process individual files
    if (!files.empty()) {
        auto fileResults = checker.processFiles(files);
        results.insert(results.end(), fileResults.begin(), fileResults.end());
    }

    // If no files or directories specified, show help
    if (results.empty()) {
        displayHelp(argv[0]);
        return 1;
    }

    // Display results
    for (const auto& result : results) {
        if (result.success) {
            std::cout << result.algorithm << ": " << result.hash << "  " << result.filename << std::endl;
        } else {
            std::cerr << "Error processing " << result.filename << ": " << result.error << std::endl;
        }
    }

    // Save to file if requested
    if (!saveFile.empty()) {
        if (checker.saveHashesToFile(results, saveFile)) {
            if (verbose) {
                std::cout << "\nHashes saved to: " << saveFile << std::endl;
            }
        } else {
            std::cerr << "Failed to save hashes to file\n";
            return 1;
        }
    }

    return 0;
}
