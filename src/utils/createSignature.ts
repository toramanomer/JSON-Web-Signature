import { Buffer } from 'node:buffer'
import { createHmac, createSign, constants } from 'node:crypto'
import { AlgorithmParameterValue } from '@/alg'

/**
 * Creates a signature based on the algorithm and key
 */
export const createSignature = (
	signingInput: string,
	algorithm: AlgorithmParameterValue,
	key: string | Buffer
): Buffer => {
	switch (algorithm) {
		// HMAC with SHA-2 Functions
		case 'HS256':
		case 'HS384':
		case 'HS512': {
			const bits = algorithm.slice(2)

			// A key of the same size as the hash output
			if (key.length * 8 < parseInt(bits))
				throw new RangeError(
					`A key with at least ${bits} bits must be used`
				)

			const hashAlg = `sha${bits}`
			return createHmac(hashAlg, key).update(signingInput).digest()
		}

		// Digital Signature with RSASSA-PKCS1-v1_5
		case 'RS256':
		case 'RS384':
		case 'RS512': {
			if (key.length * 8 < 2048)
				throw new RangeError(
					`A key of size 2048 bits or larger MUST be used with ${algorithm}`
				)

			const hashAlg = `sha${algorithm.slice(2)}`
			return createSign(hashAlg).update(signingInput).sign(key)
		}

		// Digital Signature with ECDSA
		case 'ES256':
		case 'ES384':
		case 'ES512': {
			const hashAlg = `sha${algorithm.slice(2)}`
			return createSign(hashAlg).update(signingInput).sign(key)
		}

		// Digital Signature with RSASSA-PSS
		case 'PS256':
		case 'PS384':
		case 'PS512': {
			if (key.length * 8 < 2048)
				throw new RangeError(
					`A key of size 2048 bits or larger MUST be used with ${algorithm}`
				)

			const hashAlg = `sha${algorithm.slice(2)}`

			return createSign(hashAlg)
				.update(signingInput)
				.sign({
					key,
					padding: constants.RSA_PKCS1_PSS_PADDING,
					saltLength: parseInt(algorithm.slice(2)) / 8
				})
		}

		// Should never reach here.
		default:
			throw new Error(`Unsupported algorithm: ${algorithm}`)
	}
}
