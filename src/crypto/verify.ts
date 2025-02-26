import type { Buffer } from 'node:buffer'
import type { KeyObject } from 'node:crypto'

import { type Algorithm } from '@/algorithms/algorithms'

import { verifyHmac } from '@/algorithms/hmac/verify'
import { verifyRsa } from '@/algorithms/rsa/verify'
import { verifyEcdsa } from '@/algorithms/ecdsa/verify'
import { verifyRsaPss } from '@/algorithms/rsa-pss/verify'

export const verifySignature = (
	signingInput: string,
	signature: Buffer,
	algorithm: Algorithm,
	key: KeyObject
): boolean => {
	switch (algorithm) {
		// HMAC with SHA-2 Functions
		case 'HS256':
		case 'HS384':
		case 'HS512':
			return verifyHmac({ algorithm, key, signingInput, signature })

		// Digital Signature with RSASSA-PKCS1-v1_5
		case 'RS256':
		case 'RS384':
		case 'RS512':
			return verifyRsa({ algorithm, key, signingInput, signature })

		// Digital Signature with ECDSA
		case 'ES256':
		case 'ES384':
		case 'ES512':
			return verifyEcdsa({ algorithm, key, signingInput, signature })

		// Digital Signature with RSASSA-PSS
		case 'PS256':
		case 'PS384':
		case 'PS512':
			return verifyRsaPss({ algorithm, key, signingInput, signature })

		// Should never reach here.
		default:
			throw new Error(`Unsupported algorithm: ${algorithm}`)
	}
}
