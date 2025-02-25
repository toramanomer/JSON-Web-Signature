import { Buffer } from 'node:buffer'
import { createHmac, createSign, constants } from 'node:crypto'
import { AlgorithmParameterValue } from '@/alg'

/**
 * JWS Header Parameters
 */
export interface JWSHeaderParameters {
	alg: AlgorithmParameterValue
	[key: string]: any
}

/**
 * Options for creating a JWS
 */
export interface CreateJWSOptions {
	/**
	 * The payload to sign (can be any JSON serializable value)
	 */
	payload: any

	/**
	 * The protected header parameters
	 */
	protectedHeader: JWSHeaderParameters

	/**
	 * The key used for signing
	 * - For HMAC algorithms: a string or Buffer containing the secret
	 * - For RSA and ECDSA algorithms: a private key in PEM format
	 */
	key: string | Buffer
}

/**
 * Base64Url encodes a string or buffer
 */
function base64UrlEncode(input: string | Buffer): string {
	let str = typeof input === 'string' ? input : input.toString('binary')
	let base64 = Buffer.from(str, 'binary').toString('base64')
	return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Creates a JWS according to RFC 7515
 * Returns the JWS in compact serialization format
 */
export function createJws({
	payload,
	protectedHeader,
	key
}: CreateJWSOptions): string {
	console.log(JSON.parse(protectedHeader.toString()).alg)
	// Step 1: Create the content to be used as the JWS Payload
	const payloadStr =
		typeof payload === 'string' ? payload : JSON.stringify(payload)

	// Step 2: Compute the encoded payload value
	const encodedPayload = base64UrlEncode(payloadStr)

	// Step 3 & 4: Create the header and compute the encoded header value
	const encodedHeader = base64UrlEncode(JSON.stringify(protectedHeader))

	// Step 5: Compute the JWS Signature
	const signingInput = `${encodedHeader}.${encodedPayload}`
	const signature = createSignature(signingInput, protectedHeader.alg, key)

	// Step 6: Compute the encoded signature value
	const encodedSignature = base64UrlEncode(signature)

	// Step 8: Create the JWS Compact Serialization
	return `${encodedHeader}.${encodedPayload}.${encodedSignature}`
}

/**
 * Creates a signature based on the algorithm and key
 */
function createSignature(
	signingInput: string,
	algorithm: AlgorithmParameterValue,
	key: string | Buffer
): Buffer {
	switch (algorithm) {
		// HMAC with SHA-2 Functions
		case 'HS256':
		case 'HS384':
		case 'HS512': {
			const bits = algorithm.slice(2)

			// A key of the same size as the hash output
			if (key.length * 8 < parseInt(bits))
				throw new RangeError(`A key with at least ${bits} must be used`)

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

		// Using the Algorithm "none"
		case 'none':
			return Buffer.alloc(0)

		// Should never reach here.
		default:
			throw new Error(`Unsupported algorithm: ${algorithm}`)
	}
}
