import {
	constants,
	createHmac,
	createVerify,
	KeyObject,
	timingSafeEqual
} from 'node:crypto'

import {
	AlgorithmParameterValue,
	ecdsaAlgParams,
	hmacAlgParams,
	rsaAlgParams,
	rsaPssAlgParams
} from '@/utils/alg'

export const verifySignature = (
	signingInput: string,
	signature: Buffer,
	algorithm: AlgorithmParameterValue,
	key: KeyObject
): boolean => {
	switch (algorithm) {
		// HMAC with SHA-2 Functions
		case 'HS256':
		case 'HS384':
		case 'HS512': {
			const params = hmacAlgParams[algorithm]

			if (key.type !== params.type)
				throw new Error(
					`Invalid key type for ${algorithm}. Expected "${params.type}", got "${key.type}".`
				)

			if (
				key.symmetricKeySize === undefined ||
				key.symmetricKeySize < params.minKeyBytes
			)
				throw new Error(
					`Key is too short for ${algorithm}. Expected at least ${params.minKeyBytes} bytes, got ${key.symmetricKeySize} bytes.`
				)

			// For HMAC, we compute the signature again and compare
			const expectedSignature = createHmac(params.hashAlg, key)
				.update(signingInput)
				.digest()

			// Constant-time comparison to prevent timing attacks
			return timingSafeEqual(signature, expectedSignature)
		}

		// Digital Signature with RSASSA-PKCS1-v1_5
		case 'RS256':
		case 'RS384':
		case 'RS512': {
			const params = rsaAlgParams[algorithm]

			if (key.type !== params.verifyKeyType)
				throw new Error(
					`Invalid key type for ${algorithm} during verification. Expected "${params.verifyKeyType}", got "${key.type}".`
				)

			if (key.asymmetricKeyType !== params.asymmetricKeyType)
				throw new Error(
					`Invalid key type for ${algorithm}. Expected "${params.asymmetricKeyType}", got "${key.asymmetricKeyType}".`
				)

			// Check if the key size is large enough
			const keySizeInBits = key.asymmetricKeyDetails?.modulusLength

			if (!keySizeInBits || keySizeInBits < params.minKeyBits) {
				throw new Error(
					`Key size for ${algorithm} is too small. Expected at least ${params.minKeyBits} bits, got ${keySizeInBits} bits.`
				)
			}

			return createVerify(params.hashAlg)
				.update(signingInput)
				.verify(key, signature)
		}

		// Digital Signature with ECDSA
		case 'ES256':
		case 'ES384':
		case 'ES512': {
			const params = ecdsaAlgParams[algorithm]

			if (key.type !== params.verifyKeyType)
				throw new Error(
					`Invalid key type for ${algorithm} during verification. Expected "${params.verifyKeyType}", got "${key.type}".`
				)

			if (key.asymmetricKeyType !== params.asymmetricKeyType)
				throw new Error(
					`Invalid key type for ${algorithm}. Expected "${params.asymmetricKeyType}", got "${key.asymmetricKeyType}".`
				)

			if (key.asymmetricKeyDetails?.namedCurve !== params.namedCurve)
				throw new Error(`Invalid curve for ${algorithm}.`)

			if (signature.length !== params.signatureBytes)
				throw new Error(`Signature is not 64 bytes`)

			return createVerify(params.hashAlg)
				.update(signingInput)
				.verify(key, signature)
		}

		// Digital Signature with RSASSA-PSS
		case 'PS256':
		case 'PS384':
		case 'PS512': {
			const params = rsaPssAlgParams[algorithm]
			if (key.type !== params.verifyKeyType)
				throw new Error(
					`Invalid key type for ${algorithm} during verification. Expected "${params.verifyKeyType}", got "${key.type}".`
				)

			if (key.asymmetricKeyType !== params.asymmetricKeyType) {
				throw new Error(
					`Invalid key type for ${algorithm}. Expected "${params.asymmetricKeyType}", got "${key.asymmetricKeyType}".`
				)
			}

			const keySizeInBits = key.asymmetricKeyDetails?.modulusLength
			if (!keySizeInBits || keySizeInBits < params.minKeyBits) {
				throw new Error(
					`Key size for ${algorithm} is too small. Expected at least ${params.minKeyBits} bits, got ${keySizeInBits} bits.`
				)
			}

			return createVerify(params.hashAlg)
				.update(signingInput)
				.verify(
					{
						key,
						padding: constants.RSA_PKCS1_PSS_PADDING,
						saltLength: parseInt(algorithm.slice(2)) / 8
					},
					signature
				)
		}

		// Should never reach here.
		default:
			throw new Error(`Unsupported algorithm: ${algorithm}`)
	}
}
