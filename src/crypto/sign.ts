import type { Buffer } from 'node:buffer'
import type { KeyObject } from 'node:crypto'

import { type Algorithm } from 'src/algorithms/algorithms.js'

import { signHmac } from 'src/algorithms/hmac/sign.js'
import { signRsa } from 'src/algorithms/rsa/sign.js'
import { signEcdsa } from 'src/algorithms/ecdsa/sign.js'
import { signRsaPss } from 'src/algorithms/rsa-pss/sign.js'

export const createSignature = (
	signingInput: string,
	algorithm: Algorithm,
	key: KeyObject
): Buffer => {
	switch (algorithm) {
		// HMAC with SHA-2 Functions
		case 'HS256':
		case 'HS384':
		case 'HS512':
			return signHmac({ algorithm, key, signingInput })

		// Digital Signature with RSASSA-PKCS1-v1_5
		case 'RS256':
		case 'RS384':
		case 'RS512':
			return signRsa({ algorithm, key, signingInput })

		// Digital Signature with ECDSA
		case 'ES256':
		case 'ES384':
		case 'ES512':
			return signEcdsa({ algorithm, key, signingInput })

		// Digital Signature with RSASSA-PSS
		case 'PS256':
		case 'PS384':
		case 'PS512':
			return signRsaPss({ algorithm, key, signingInput })

		// Should never reach here.
		default:
			throw new Error(`Unsupported algorithm: ${algorithm}`)
	}
}
