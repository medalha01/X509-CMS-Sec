## Overview

This C++ program leverages OpenSSL to perform cryptographic operations, focusing on verifying digital signatures. It supports CMS (Cryptographic Message Syntax) signature verification, decoding certificates and CRLs (Certificate Revocation Lists) in PEM and DER formats, and validating certificates against trusted ones.

## Dependencies

- OpenSSL: Required for cryptographic functionalities.

## Features

- **Signature Verification**: Verifies CMS signatures against a certificate chain.
- **Certificate and CRL Decoding**: Decodes in both PEM and DER formats.
- **Certificate Validation**: Checks against trusted certificates, revocation, and expiration.

## Usage

Compile and run the program as follows:

```bash
g++ -o verify_signatures verify_signatures.cpp -lssl -lcrypto```
