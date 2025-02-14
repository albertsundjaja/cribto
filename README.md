# 🔐 Cribto - Rust Encryption CLI

**Cribto** is a command-line tool for encryption, decryption, and key generation in Rust.

## 🚀 Features

- 🔑 **Generate RSA Key Pairs** (2048-bit)
- 🔒 **Encrypt Data** with RSA Public Key
- 🔓 **Decrypt Data** with RSA Private Key
- 📂 **Support for File & Text Encryption**
- 🦀 **Built with Rust for High Performance & Security**
- more features coming soon

## 📦 Installation

To install Cribto, clone this repository and build the project:
```sh
# Clone the repository
git clone https://github.com/yourusername/cribto.git
cd cribto

# Build the project
cargo build --release

# Run Cribto
./target/release/cribto --help
```

## 🛠️ Usage

### **Generate an RSA Key Pair**
```sh
cribto generate
```
This creates `private_key.pem` and `public_key.pem` in the current directory.

### **Encrypt a File**
```sh
cribto encrypt -i secret.txt -o encrypted.bin -k public_key.pem
```
This encrypts `secret.txt` using the RSA public key.

### **Decrypt a File**
```sh
cribto decrypt -i encrypted.bin -o decrypted.txt -k private_key.pem
```
This decrypts `encrypted.bin` using the RSA private key.

### **Encrypt a String**
```sh
echo "Hello, world!" | cribto encrypt -k public_key.pem
```

### **Decrypt a String**
```sh
echo "<encrypted_string>" | cribto decrypt -k private_key.pem
```

## 📜 License

This project is licensed under the MIT License.

## 🤝 Contributing

Pull requests are welcome! If you'd like to contribute, please open an issue first to discuss your idea.