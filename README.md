# Chelonia Crypto Library

A cryptographic library providing secure key management, encryption, and signature operations for Node.js and browser applications.

## Installation

```bash
npm install @chelonia/crypto
```

## Features

- Key generation and management for various cryptographic algorithms
- Password-based key derivation
- Message signing and verification
- Symmetric and asymmetric encryption
- Support for ed25519, curve25519, and XSalsa20-Poly1305

## Supported Algorithms

- `edwards25519sha512batch` - Ed25519 for signatures
- `curve25519xsalsa20poly1305` - Curve25519 for asymmetric encryption
- `xsalsa20poly1305` - XSalsa20-Poly1305 for symmetric encryption

## Usage Examples

### Key Generation

```typescript
import { keygen, EDWARDS25519SHA512BATCH, CURVE25519XSALSA20POLY1305, XSALSA20POLY1305 } from '@chelonia/crypto';

// Generate an Ed25519 key pair for signing
const signingKey = keygen(EDWARDS25519SHA512BATCH);

// Generate a Curve25519 key pair for asymmetric encryption
const encryptionKey = keygen(CURVE25519XSALSA20POLY1305);

// Generate a symmetric encryption key
const symmetricKey = keygen(XSALSA20POLY1305);
```

### Serializing and Deserializing Keys

```typescript
import { serializeKey, deserializeKey } from '@chelonia/crypto';

// Serialize a key (with secret key)
const serializedKey = serializeKey(key, true);

// Serialize a key (public key only)
const serializedPublicKey = serializeKey(key, false);

// Deserialize a key
const deserializedKey = deserializeKey(serializedKey);
```

### Password-Based Key Derivation

```typescript
import { deriveKeyFromPassword, generateSalt, EDWARDS25519SHA512BATCH } from '@chelonia/crypto';

// Generate a random salt
const salt = generateSalt();

// Derive a key from a password and salt
const key = await deriveKeyFromPassword(EDWARDS25519SHA512BATCH, 'password123', salt);
```

### Signing and Verifying

```typescript
import { sign, verifySignature, EDWARDS25519SHA512BATCH, keygen } from '@chelonia/crypto';

const key = keygen(EDWARDS25519SHA512BATCH);
const data = 'message to sign';

// Sign a message
const signature = sign(key, data);

// Verify a signature
try {
  verifySignature(key, data, signature);
  console.log('Signature is valid');
} catch (error) {
  console.error('Signature verification failed:', error);
}
```

### Encryption and Decryption

```typescript
import { encrypt, decrypt, keygen, CURVE25519XSALSA20POLY1305, XSALSA20POLY1305 } from '@chelonia/crypto';

// Asymmetric encryption
const asymmetricKey = keygen(CURVE25519XSALSA20POLY1305);
const encryptedData = encrypt(asymmetricKey, 'secret message');
const decryptedData = decrypt(asymmetricKey, encryptedData);

// Symmetric encryption
const symmetricKey = keygen(XSALSA20POLY1305);
const encryptedWithSymmetric = encrypt(symmetricKey, 'secret message');
const decryptedWithSymmetric = decrypt(symmetricKey, encryptedWithSymmetric);

// With additional data (AD)
const encryptedWithAD = encrypt(symmetricKey, 'secret message', 'additional data');
const decryptedWithAD = decrypt(symmetricKey, encryptedWithAD, 'additional data');
```

## API Reference

### Key Management

- `keygen(type: string): Key` - Generate a key pair of the specified type
- `serializeKey(key: Key, saveSecretKey: boolean): string` - Serialize a key to JSON
- `deserializeKey(data: string): Key` - Deserialize a key from JSON
- `keygenOfSameType(key: Key | string): Key` - Generate a new key of the same type
- `keyId(key: Key | string): string` - Generate a unique ID for a key
- `generateSalt(): string` - Generate a random salt
- `deriveKeyFromPassword(type: string, password: string, salt: string): Promise<Key>` - Derive a key from a password

### Cryptographic Operations

- `sign(key: Key | string, data: string): string` - Sign data with a key
- `verifySignature(key: Key | string, data: string, signature: string): void` - Verify a signature
- `encrypt(key: Key | string, data: string, ad?: string): string` - Encrypt data with a key
- `decrypt(key: Key | string, data: string, ad?: string): string` - Decrypt data with a key

## License

AGPL 3.0.
