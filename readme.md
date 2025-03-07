# JSON Web Signature (JWS)

Implementation of JSON Web Signature (JWS) according to [RFC 7515](https://tools.ietf.org/html/rfc7515).

> **Zero Dependencies**: This project relies solely on Node.js built-in modules and has no production dependencies.

## Serialization Formats

| Feature                          | JWS Compact Serialization     | General JWS JSON Serialization          | Flattened JWS JSON Serialization |
| -------------------------------- | ----------------------------- | --------------------------------------- | -------------------------------- |
| **Compact Format**               | ✅ Yes                        | ❌ No                                   | ❌ No                            |
| **URL-Safe**                     | ✅ Yes (Base64url encoding)   | ❌ No (Uses standard JSON)              | ❌ No (Uses standard JSON)       |
| **Readability**                  | ❌ Not human-readable         | ✅ More human-readable                  | ✅ More human-readable           |
| **Supports Multiple Signatures** | ❌ No (Single signature only) | ✅ Yes (Multiple signatures)            | ❌ No (Single signature only)    |
| **JOSE Header**                  | Protected only                | Protected & Unprotected (per signature) | Protected & Unprotected          |

## Key Requirements

The keys for signing and/or verification **must be an instance of [`KeyObject`](https://nodejs.org/docs/latest-v22.x/api/crypto.html#class-keyobject)**. The following subsections describe the required properties for the key used in signing and verification operations for each supported algorithm.

### HMAC with SHA-2 Functions (`HS256`, `HS384`, `HS512`)

HMAC-based algorithms use a **symmetric key**, meaning the **same key** is used for both **signing** and **verification**.  
The key **must be at least as long as the hash output size**.

#### **Example: Creating a 256-bit Secret Key for HS256**

```typescript
import { generateKeySync } from 'node:crypto'

const key = generateKeySync('hmac', { length: 256 })

console.log(key.type) // "secret"
console.log(key.symmetricKeySize) // 32 (256 bits)
```

| `"alg"` Param Value | Key Type (`keyObject.type`) | Minimum Key Size    | Signing Key | Verification Key |
| ------------------- | --------------------------- | ------------------- | ----------- | ---------------- |
| `HS256`             | `"secret"`                  | 32 bytes (256 bits) | Same key    | Same key         |
| `HS384`             | `"secret"`                  | 48 bytes (384 bits) | Same key    | Same key         |
| `HS512`             | `"secret"`                  | 64 bytes (512 bits) | Same key    | Same key         |

### Digital Signature with RSASSA-PKCS1-v1_5 (`RS256`, `RS384`, `RS512`)

These algorithms use **asymmetric RSA keys** with **PKCS#1 v1.5 padding** for digital signatures.  
A **private key** is required for signing, while the corresponding **public key** is used for verification.

#### **Example: Generating an RSA Key Pair for RS256**

```typescript
import { generateKeyPairSync } from 'node:crypto'

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
	modulusLength: 2048
})

console.log(privateKey.type) // "private"
console.log(publicKey.type) // "public"
console.log(privateKey.asymmetricKeyType) // "rsa"
console.log(publicKey.asymmetricKeyType) // "rsa"
```

| `"alg"` Param Value | Key Type (`keyObject.type`)                       | Asymmetric Key Type (`keyObject.asymmetricKeyType`) | Minimum Key Size |
| ------------------- | ------------------------------------------------- | --------------------------------------------------- | ---------------- |
| `RS256`             | `"private"` (signing) / `"public"` (verification) | `"rsa"`                                             | 2048 bits        |
| `RS384`             | `"private"` (signing) / `"public"` (verification) | `"rsa"`                                             | 2048 bits        |
| `RS512`             | `"private"` (signing) / `"public"` (verification) | `"rsa"`                                             | 2048 bits        |

### Digital Signature with ECDSA (`ES256`, `ES384`, `ES512`)

These algorithms use **Elliptic Curve Digital Signature Algorithm (ECDSA)** for digital signatures.  
A **private key** is required for signing, while the corresponding **public key** is used for verification.

#### **Example: Generating an EC Key Pair for ES256**

```typescript
import { generateKeyPairSync } from 'node:crypto'

const { privateKey, publicKey } = generateKeyPairSync('ec', {
	namedCurve: 'P-256'
})

console.log(privateKey.type) // "private"
console.log(publicKey.type) // "public"
console.log(privateKey.asymmetricKeyType) // "ec"
console.log(publicKey.asymmetricKeyType) // "ec"
```

| `"alg"` Param Value | Key Type (`keyObject.type`)                       | Asymmetric Key Type (`keyObject.asymmetricKeyType`) | Required Curve       |
| ------------------- | ------------------------------------------------- | --------------------------------------------------- | -------------------- |
| `ES256`             | `"private"` (signing) / `"public"` (verification) | `"ec"`                                              | `P-256` (prime256v1) |
| `ES384`             | `"private"` (signing) / `"public"` (verification) | `"ec"`                                              | `P-384` (secp384r1)  |
| `ES512`             | `"private"` (signing) / `"public"` (verification) | `"ec"`                                              | `P-521` (secp521r1)  |

### Digital Signature with RSASSA-PSS (`PS256`, `PS384`, `PS512`)

These algorithms use **RSA Probabilistic Signature Scheme (RSASSA-PSS)**.  
A **private key** is required for signing, while the corresponding **public key** is used for verification.

#### **Example: Generating an RSA Key Pair for PS256**

```typescript
import { generateKeyPairSync } from 'node:crypto'

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
	modulusLength: 2048
})

console.log(privateKey.type) // "private"
console.log(publicKey.type) // "public"
console.log(privateKey.asymmetricKeyType) // "rsa-pss"
console.log(publicKey.asymmetricKeyType) // "rsa-pss"
```

| `"alg"` Param Value | Key Type (`keyObject.type`)                       | Asymmetric Key Type (`keyObject.asymmetricKeyType`) | Minimum Key Size |
| ------------------- | ------------------------------------------------- | --------------------------------------------------- | ---------------- |
| `PS256`             | `"private"` (signing) / `"public"` (verification) | `"rsa-pss"`                                         | 2048 bits        |
| `PS384`             | `"private"` (signing) / `"public"` (verification) | `"rsa-pss"`                                         | 2048 bits        |
| `PS512`             | `"private"` (signing) / `"public"` (verification) | `"rsa-pss"`                                         | 2048 bits        |
