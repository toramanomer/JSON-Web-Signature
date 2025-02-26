import {
	constants,
	createHmac,
	createVerify,
	timingSafeEqual
} from 'node:crypto'
import { AlgorithmParameterValue } from '@/alg'

export const verifySignature = (
	signingInput: string,
	signature: Buffer,
	algorithm: AlgorithmParameterValue,
	key: Buffer
): boolean => {
	switch (algorithm) {
		// HMAC with SHA-2 Functions
		case 'HS256':
		case 'HS384':
		case 'HS512': {
			const bits = algorithm.slice(2)
			const hashAlg = `sha${bits}`

			// For HMAC, we compute the signature again and compare
			const expectedSignature = createHmac(hashAlg, key)
				.update(signingInput)
				.digest()

			// Constant-time comparison to prevent timing attacks
			return timingSafeEqual(signature, expectedSignature)
		}

		// Digital Signature with RSASSA-PKCS1-v1_5
		case 'RS256':
		case 'RS384':
		case 'RS512': {
			const hashAlg = `sha${algorithm.slice(2)}`
			return createVerify(hashAlg)
				.update(signingInput)
				.verify(key, signature)
		}

		// Digital Signature with ECDSA
		case 'ES256':
		case 'ES384':
		case 'ES512': {
			const hashAlg = `sha${algorithm.slice(2)}`
			return createVerify(hashAlg)
				.update(signingInput)
				.verify(key, signature)
		}

		// Digital Signature with RSASSA-PSS
		case 'PS256':
		case 'PS384':
		case 'PS512': {
			const hashAlg = `sha${algorithm.slice(2)}`
			return createVerify(hashAlg)
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
