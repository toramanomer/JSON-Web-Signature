import { generateKeyPairSync, generateKeySync } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import { verifyHmac } from '../../../../src/algorithms/hmac/verify'
import { InvalidKeyError } from '../../../../src/algorithms/InvalidKeyError'
import { hmacParams } from '../../../../src/algorithms/hmac/params'
import { keys } from '../../../../src/utils/object'

describe('verifyHmac', () => {
	describe('When using invalid key', () => {
		const algorithms = keys(hmacParams)
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
				).toThrow(InvalidKeyError.invalidType(algorithm, 'secret'))
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
				).toThrow(InvalidKeyError.invalidType(algorithm, 'secret'))
			}
		)

		// Incorrect key size
		it.for(algorithms)(
			'should throw when key size is too small for %s',
			algorithm => {
				const minBytes = hmacParams[algorithm].minKeyBytes
				const key = generateKeySync('hmac', {
					length: minBytes * 8 - 1
				})

				expect(() =>
					verifyHmac({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError.invalidSize(algorithm, minBytes))
			}
		)
	})
})
