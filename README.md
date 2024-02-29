## Overview

This C++ program leverages OpenSSL to perform cryptographic operations, focusing on verifying digital signatures. It supports CMS (Cryptographic Message Syntax) signature verification, decoding certificates and CRLs (Certificate Revocation Lists) in PEM and DER formats, and validating certificates against trusted ones.

## Dependencies

- OpenSSL: Required for cryptographic functionalities.

## Features

- **Signature Verification**: Verifies CMS signatures against a certificate chain.
- **Certificate and CRL Decoding**: Decodes in both PEM and DER formats.
- **Certificate Validation**: Checks against trusted certificates, revocation, and expiration.
- **Dynamic Signature and Certificate Handling**: Includes functionalities to add signer certificates to signatures, manage certificate chains, and work with certificate revocation lists effectively.
- **Utility Functions**: Provides a suite of utility functions for certificate information retrieval, including issuer and subject details, serial number, validity period, revocation status, and more.

## Usage

Compile and run the program as follows:

```bash
> g++ -o verify_signatures verify_signatures.cpp -lssl -lcrypto
```

Run the program by executing the compiled binary, passing the required arguments for the specific operation you wish to perform.

## Security Note
This tool is intended for educational and testing purposes. Users should be aware of the security implications of digital signature verification and certificate handling in production environments. Proper understanding and cautious handling of cryptographic materials are advised.
