import { generateKeyPairSync, generateKeySync } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import { verifyHmac } from '../../../../src/algorithms/hmac/verify'
import { InvalidKeyError } from '../../../../src/algorithms/InvalidKeyError'
import {
	hmacParams,
	type HmacAlgorithm
} from '../../../../src/algorithms/hmac/params'

describe('verifyHmac', () => {
	describe('When using invalid key', () => {
		const algorithms = Object.keys(hmacParams) as HmacAlgorithm[]
		const signature = Buffer.from('dummy-signature')
		const signingInput = 'test'

		// Private key
		it.for(algorithms)(
			'should throw when private key is used with %s',
			algorithm => {
				const { privateKey: key } = generateKeyPairSync('rsa', {
					modulusLength: 2048
				})

				expect(() =>
					verifyHmac({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError)
			}
		)

		// Public key
		it.for(algorithms)(
			'should throw when public key is used with %s',
			algorithm => {
				const { publicKey: key } = generateKeyPairSync('rsa', {
					modulusLength: 2048
				})

				expect(() =>
					verifyHmac({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError)
			}
		)

		// Incorrect key size
		it.for(algorithms)(
			'should throw when key size is too small for %s',
			algorithm => {
				const minBytes = hmacParams[algorithm].minKeyBytes
				const key = generateKeySync('hmac', {
					length: (minBytes - 1) * 8
				})

				expect(() =>
					verifyHmac({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError)
			}
		)
	})
})
