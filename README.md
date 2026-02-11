# 🔒 C++ File Integrity Checker

A comprehensive cybersecurity-focused C++ application that calculates cryptographic hashes to detect and verify file integrity. This project demonstrates various modern C++ concepts, best practices, and security principles.

## 📋 Table of Contents
- [Features](#-features)
- [C++ Concepts Explained](#-c-concepts-explained)
- [Build Instructions](#-build-instructions)
- [Usage](#-usage)
- [Security Concepts](#-security-concepts)
- [Project Architecture](#-project-architecture)
- [Examples](#-examples)
- [Educational Value](#-educational-value)

## ✨ Features

- **Multiple Hash Algorithms**: Support for MD5, SHA-1, SHA-256, and SHA-512
- **Batch Processing**: Hash multiple files in a single command
- **Directory Scanning**: Recursively scan directories and hash all files
- **Hash Verification**: Verify file integrity against known hash values
- **Database Storage**: Save and load hash databases for file monitoring
- **Verbose Mode**: Detailed output for debugging and monitoring
- **Modern C++ Implementation**: Uses C++17 features and modern OpenSSL EVP API

## 🎓 C++ Concepts Explained

This project demonstrates numerous important C++ concepts:

### 1. **Object-Oriented Programming (OOP)**

```cpp
class FileIntegrityChecker {
private:
    bool verbose;
    HashAlgorithm algorithm;
public:
    FileIntegrityChecker(bool verbose, HashAlgorithm algo);
    HashResult calculateHash(const std::string& filepath);
};
```

**What we learn:**
- **Encapsulation**: Private member variables (`verbose`, `algorithm`) are hidden from external access
- **Member Functions**: Methods like `calculateHash()` operate on object data
- **Constructor**: Initialize object state with custom parameters
- **Information Hiding**: Implementation details are kept private

### 2. **Enumerations (enum class)**

```cpp
enum class HashAlgorithm {
    MD5,
    SHA1,
    SHA256,
    SHA512
};
```

**What we learn:**
- **Type Safety**: `enum class` provides strongly-typed enumerations
- **Scope**: Values are scoped to the enum (e.g., `HashAlgorithm::SHA256`)
- **No Implicit Conversions**: Cannot accidentally convert to/from integers

### 3. **Structures (struct)**

```cpp
struct HashResult {
    std::string filename;
    std::string hash;
    std::string algorithm;
    bool success;
    std::string error;
};
```

**What we learn:**
- **Data Aggregation**: Group related data into a single type
- **Value Semantics**: Structures are copyable and movable by default
- **Public by Default**: All members are accessible (unlike classes)

### 4. **Standard Template Library (STL)**

```cpp
std::vector<HashResult> results;           // Dynamic array
std::map<std::string, bool> verificationResults;  // Key-value pairs
std::ifstream file(filepath, std::ios::binary);   // File input stream
```

**What we learn:**
- **Containers**: `vector`, `map` for dynamic data storage
- **Iterators**: Traversing collections efficiently
- **Streams**: File I/O with `ifstream` and `ofstream`
- **Memory Management**: Automatic memory handling (no manual `new`/`delete`)

### 5. **Modern C++17 Filesystem Library**

```cpp
namespace fs = std::filesystem;
if (fs::exists(filepath) && fs::is_regular_file(filepath)) {
    // Process file
}
```

**What we learn:**
- **Namespace Aliases**: Shorter names for long namespaces
- **Path Manipulation**: Cross-platform file system operations
- **Type Safety**: Compile-time checked filesystem operations

### 6. **Exception Handling**

```cpp
try {
    if (!file) {
        throw std::runtime_error("Cannot open file");
    }
} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
}
```

**What we learn:**
- **Error Propagation**: Handling exceptional conditions
- **RAII (Resource Acquisition Is Initialization)**: Automatic cleanup on exceptions
- **Standard Exceptions**: Using `std::runtime_error` and base class `std::exception`

### 7. **RAII (Resource Acquisition Is Initialization)**

```cpp
{
    std::ifstream file(filepath, std::ios::binary);
    // File is automatically opened
    // ... use file ...
}  // File is automatically closed here
```

**What we learn:**
- **Automatic Resource Management**: Resources tied to object lifetime
- **Destructor Cleanup**: File handles, memory, etc., cleaned up automatically
- **Exception Safety**: Resources are released even if exceptions occur

### 8. **Memory Management with Smart Pointers**

```cpp
EVP_MD_CTX* ctx = EVP_MD_CTX_new();
// ... use context ...
EVP_MD_CTX_free(ctx);  // Manual cleanup for C API
```

**What we learn:**
- **Manual Memory Management**: When interfacing with C libraries
- **Importance of Cleanup**: Preventing memory leaks
- **Future Improvement**: Could use `std::unique_ptr` with custom deleter

### 9. **String Manipulation and Formatting**

```cpp
std::stringstream ss;
ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
std::string result = ss.str();
```

**What we learn:**
- **String Streams**: Building strings efficiently
- **I/O Manipulators**: `std::hex`, `std::setw`, `std::setfill` for formatting
- **Type Conversions**: Converting between numeric and string types

### 10. **Algorithm and Functional Programming**

```cpp
std::transform(actualHash.begin(), actualHash.end(), 
               actualHash.begin(), ::tolower);
```

**What we learn:**
- **STL Algorithms**: `std::transform` for element-wise operations
- **Iterators**: Begin/end iterator pattern
- **Function Objects**: Using standard functions with algorithms

### 11. **Range-Based For Loops (C++11)**

```cpp
for (const auto& entry : fs::directory_iterator(dirpath)) {
    if (entry.is_regular_file()) {
        results.push_back(calculateHash(entry.path().string()));
    }
}
```

**What we learn:**
- **Cleaner Syntax**: More readable than traditional loops
- **Type Deduction**: `auto` keyword for automatic type inference
- **Reference Semantics**: Using `const auto&` to avoid copies

### 12. **Lambda Functions (Implicit in modern code)**

While not explicitly shown, the project structure supports lambda functions:

```cpp
// Example of how lambdas could be used
auto hashFile = [&checker](const std::string& file) {
    return checker.calculateHash(file);
};
```

**What we learn:**
- **Anonymous Functions**: Functions without names
- **Closures**: Capturing variables from surrounding scope
- **Functional Programming**: Treating functions as first-class objects

### 13. **Command-Line Argument Parsing**

```cpp
for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
        displayHelp(argv[0]);
        return 0;
    }
    // ... more argument parsing
}
```

**What we learn:**
- **C-style Arrays**: `argc` and `argv[]` from C
- **String Comparison**: Using `==` operator for strings
- **User Interface Design**: Command-line option handling

### 14. **Const Correctness**

```cpp
const EVP_MD* getMessageDigest() const {
    // This function doesn't modify object state
}

void processResults(const std::vector<HashResult>& results) {
    // Results are read-only in this function
}
```

**What we learn:**
- **Const Member Functions**: Promise not to modify object state
- **Const References**: Pass large objects without copying
- **Const Pointers**: Indicating immutability

## 🔧 Build Instructions

### Prerequisites
- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.10 or higher
- OpenSSL development libraries

### Installation

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install build-essential cmake libssl-dev
```

#### macOS
```bash
brew install cmake openssl
```

#### Fedora/RHEL
```bash
sudo dnf install gcc-c++ cmake openssl-devel
```

### Build Steps

```bash
# Clone the repository
git clone https://github.com/orgito1015/Cpp-File-Integrity-Checker.git
cd Cpp-File-Integrity-Checker

# Create build directory
mkdir build
cd build

# Configure with CMake
cmake ..

# Compile
make

# The executable will be: ./file_integrity_checker
```

## 📖 Usage

### Basic Usage

```bash
# Calculate SHA-256 hash of a single file
./file_integrity_checker file.txt

# Calculate hash of multiple files
./file_integrity_checker file1.txt file2.txt file3.txt
```

### Using Different Hash Algorithms

```bash
# MD5 hash
./file_integrity_checker -a md5 file.txt

# SHA-1 hash
./file_integrity_checker -a sha1 file.txt

# SHA-512 hash
./file_integrity_checker -a sha512 file.txt
```

### Directory Operations

```bash
# Hash all files in a directory
./file_integrity_checker -d /path/to/directory

# Recursively hash all files in directory tree
./file_integrity_checker -d /path/to/directory -r
```

### Verification Operations

```bash
# Verify a file against a known hash
./file_integrity_checker -c <expected-hash> file.txt

# Save hashes to a database file
./file_integrity_checker -s database.txt file1.txt file2.txt

# Verify files from database
./file_integrity_checker -l database.txt
```

### Verbose Mode

```bash
# Enable detailed output
./file_integrity_checker -v -d /path/to/directory
```

## 🔐 Security Concepts

### 1. **Cryptographic Hash Functions**

A cryptographic hash function takes input data and produces a fixed-size string (hash) that uniquely represents that data.

**Properties:**
- **Deterministic**: Same input always produces same hash
- **One-way**: Cannot recover original data from hash
- **Avalanche Effect**: Small input change drastically changes hash
- **Collision Resistant**: Hard to find two inputs with same hash

### 2. **File Integrity Checking**

File integrity checking verifies that files haven't been tampered with by:
1. Computing a hash of the original file
2. Storing that hash securely
3. Later, recomputing the hash and comparing with stored value
4. If hashes match → file is unchanged
5. If hashes differ → file has been modified

### 3. **Hash Algorithm Comparison**

| Algorithm | Output Size | Security Status | Use Case |
|-----------|-------------|-----------------|----------|
| MD5       | 128 bits    | ❌ Broken       | Legacy systems only |
| SHA-1     | 160 bits    | ⚠️ Deprecated   | Git commits (transitioning) |
| SHA-256   | 256 bits    | ✅ Secure       | **Recommended for security** |
| SHA-512   | 512 bits    | ✅ Secure       | High security requirements |

**Recommendation**: Use SHA-256 or SHA-512 for security applications.

### 4. **Use Cases in Cybersecurity**

- **Malware Detection**: Compare file hashes with known malware signatures
- **Intrusion Detection**: Monitor critical system files for unauthorized changes
- **Digital Forensics**: Verify evidence integrity in investigations
- **Software Distribution**: Verify downloaded files haven't been tampered with
- **Compliance**: Meet regulatory requirements for data integrity

## 🏗️ Project Architecture

### Code Structure

```
Cpp-File-Integrity-Checker/
├── src/
│   └── main.cpp          # Main application code
├── CMakeLists.txt        # Build configuration
├── README.md             # This file
└── .gitignore           # Git ignore rules
```

### Design Patterns Used

1. **Class-Based Design**: `FileIntegrityChecker` class encapsulates all functionality
2. **Strategy Pattern**: Different hash algorithms selected at runtime
3. **Result Object Pattern**: `HashResult` struct contains operation results
4. **Command Pattern**: Command-line options control behavior

### OpenSSL EVP API

The project uses the modern OpenSSL EVP (Envelope) API instead of deprecated low-level functions:

```cpp
EVP_MD_CTX* ctx = EVP_MD_CTX_new();           // Create context
EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr); // Initialize
EVP_DigestUpdate(ctx, data, length);           // Update with data
EVP_DigestFinal_ex(ctx, hash, &hash_len);      // Finalize
EVP_MD_CTX_free(ctx);                          // Cleanup
```

**Benefits:**
- Algorithm-agnostic interface
- Better performance optimizations
- Future-proof against OpenSSL updates
- Thread-safe operations

## 💡 Examples

### Example 1: Basic File Integrity Check

```bash
# Initial hash of important file
$ ./file_integrity_checker /etc/passwd
SHA-256: a1b2c3d4e5f6... /etc/passwd

# Save hash for later verification
$ ./file_integrity_checker -s system_hashes.db /etc/passwd

# Later, verify the file hasn't changed
$ ./file_integrity_checker -l system_hashes.db
/etc/passwd: PASS
```

### Example 2: Monitoring a Project Directory

```bash
# Hash all files in a project
$ ./file_integrity_checker -r -d ./my_project -s project_baseline.db

# After some time, check for any modifications
$ ./file_integrity_checker -l project_baseline.db
./my_project/file1.cpp: PASS
./my_project/file2.cpp: FAIL  # This file was modified!
./my_project/file3.h: PASS
```

### Example 3: Verifying Downloaded Software

```bash
# Download a file and its published SHA-256 hash
# Verify the download integrity
$ ./file_integrity_checker -c 1234abcd5678efgh... downloaded_software.tar.gz
downloaded_software.tar.gz: VERIFIED
```

## 🎯 Educational Value

### What You Learn From This Project

1. **C++ Programming**
   - Modern C++17 features
   - Object-oriented design
   - STL containers and algorithms
   - File I/O operations
   - Error handling

2. **Cryptography**
   - Hash function properties
   - Security considerations
   - Algorithm selection
   - OpenSSL library usage

3. **Software Engineering**
   - Command-line tool design
   - User interface considerations
   - Error handling strategies
   - Code organization

4. **Cybersecurity**
   - File integrity concepts
   - Intrusion detection principles
   - Digital forensics basics
   - Security best practices

5. **Build Systems**
   - CMake configuration
   - Cross-platform compilation
   - Library linking
   - Dependency management

## ⚠️ Important Notes

- **Educational Purpose**: This tool is designed for learning and educational purposes
- **Security Considerations**: For production use, consider additional features like:
  - Digital signatures for hash databases
  - Secure storage of hash values
  - Access control and auditing
  - Integration with security information and event management (SIEM) systems
- **Performance**: For very large files or directories, consider:
  - Parallel processing
  - Incremental hashing
  - Caching mechanisms

## 🤝 Contributing

This is an educational project. Contributions that improve code quality, add features, or enhance documentation are welcome!

## 📄 License

Educational purpose only. Use at your own risk.

## 🔗 Additional Resources

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [C++ Reference](https://en.cppreference.com/)
- [CMake Documentation](https://cmake.org/documentation/)
- [NIST on Cryptographic Hash Functions](https://csrc.nist.gov/projects/hash-functions)

---

**Note**: This project demonstrates modern C++ programming and cryptographic concepts. Always use appropriate security measures in production environments.
