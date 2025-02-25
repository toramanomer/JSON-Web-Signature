# JSON Web Signature (JWS)

Implementation of JSON Web Signature (JWS) according to [RFC 7515](https://tools.ietf.org/html/rfc7515).

## Serialization Formats

| Feature                          | JWS Compact Serialization     | General JWS JSON Serialization          | Flattened JWS JSON Serialization |
| -------------------------------- | ----------------------------- | --------------------------------------- | -------------------------------- |
| **Compact Format**               | ✅ Yes                        | ❌ No                                   | ❌ No                            |
| **URL-Safe**                     | ✅ Yes (Base64url encoding)   | ❌ No (Uses standard JSON)              | ❌ No (Uses standard JSON)       |
| **Readability**                  | ❌ Not human-readable         | ✅ More human-readable                  | ✅ More human-readable           |
| **Supports Multiple Signatures** | ❌ No (Single signature only) | ✅ Yes (Multiple signatures)            | ❌ No (Single signature only)    |
| **JOSE Header**                  | Protected only                | Protected & Unprotected (per signature) | Protected & Unprotected          |
