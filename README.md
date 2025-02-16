# 🔐 Cribto - Rust Encryption CLI

**Cribto** is a command-line tool for encryption, decryption, and key generation in Rust.

## 🚀 Features

- 🔑 **Generate RSA Key Pairs** (4096-bit)
- 🔒 **Encrypt Data** with RSA Public Key or Password (argon2)
- 🔓 **Decrypt Data** with RSA Private Key or Password (argon2)
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
cribto encrypt public_key.pem secret.txt
```
This encrypts `secret.txt` using the RSA public key and output a file called `encrypted`.

### **Decrypt a File**
```sh
cribto decrypt private_key.pem encrypted
```
This decrypts `encrypted` using the RSA private key and output a file called `decrypted`.

### **Encrypt a String**
```sh
cribto encrypt -i text public_key.pem "Hello, World!"
```

### **Decrypt a String**
```sh
cribto encrypt -i text private_key.pem "<encrypted_text>"
```

## 📜 License

This project is licensed under the MIT License.

## 🤝 Contributing

Pull requests are welcome! If you'd like to contribute, please open an issue first to discuss your idea.