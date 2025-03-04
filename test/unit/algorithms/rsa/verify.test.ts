import { generateKeyPairSync, generateKeySync } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import { verifyRsa } from '../../../../src/algorithms/rsa/verify'
import { InvalidKeyError } from '../../../../src/algorithms/InvalidKeyError'
import { rsaParams } from '../../../../src/algorithms/rsa/params'
import { keys } from '../../../../src/utils/object'

describe('verifyRsa', () => {
	describe('When using invalid key', () => {
		const algorithms = keys(rsaParams)
		const signature = Buffer.from('dummy-signature')
		const signingInput = 'test'

		// Secret key
		it.for(algorithms)(
			'should throw when secret key is used with %s',
			algorithm => {
				const key = generateKeySync('hmac', { length: 256 })

				expect(() =>
					verifyRsa({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError.invalidType(algorithm, 'public'))
			}
		)

		// Private key
		it.for(algorithms)(
			'should throw when private key is used with %s',
			algorithm => {
				const { privateKey: key } = generateKeyPairSync('rsa', {
					modulusLength: rsaParams[algorithm].minKeyBits
				})

				expect(() =>
					verifyRsa({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError.invalidType(algorithm, 'public'))
			}
		)

		// Wrong asymmetric key type
		it.for(algorithms)(
			'should throw when EC key is used with %s',
			algorithm => {
				const { publicKey: key } = generateKeyPairSync('ec', {
					namedCurve: 'P-256'
				})

				expect(() =>
					verifyRsa({ algorithm, key, signature, signingInput })
				).toThrow(
					InvalidKeyError.invalidAsymmetricKeyType(algorithm, 'rsa')
				)
			}
		)

		// Key too small
		it.for(algorithms)(
			'should throw when key size is too small for %s',
			algorithm => {
				const { publicKey: key } = generateKeyPairSync('rsa', {
					modulusLength: rsaParams[algorithm].minKeyBits - 1
				})

				expect(() =>
					verifyRsa({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError.invalidSize(algorithm, 2048 / 8))
			}
		)
	})
})
