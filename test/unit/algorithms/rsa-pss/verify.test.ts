import { generateKeyPairSync, generateKeySync } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import { verifyRsaPss } from '../../../../src/algorithms/rsa-pss/verify'
import { InvalidKeyError } from '../../../../src/algorithms/InvalidKeyError'
import { rsaPssParams } from '../../../../src/algorithms/rsa-pss/params'
import { keys } from '../../../../src/utils/object'

describe('verifyRsaPss', () => {
	describe('When using invalid key', () => {
		const algorithms = keys(rsaPssParams)
		const signature = Buffer.from('dummy-signature')
		const signingInput = 'test'

		// Secret key
		it.for(algorithms)(
			'should throw when secret key is used with %s',
			algorithm => {
				const key = generateKeySync('hmac', { length: 256 })

				expect(() =>
					verifyRsaPss({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError.invalidType(algorithm, 'public'))
			}
		)

		// Private key
		it.for(algorithms)(
			'should throw when private key is used with %s',
			algorithm => {
				const { privateKey: key } = generateKeyPairSync('rsa-pss', {
					modulusLength: rsaPssParams[algorithm].minKeyBits
				})

				expect(() =>
					verifyRsaPss({ algorithm, key, signature, signingInput })
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
					verifyRsaPss({ algorithm, key, signature, signingInput })
				).toThrow(
					InvalidKeyError.invalidAsymmetricKeyType(
						algorithm,
						'rsa-pss'
					)
				)
			}
		)

		// Key too small
		it.for(algorithms)(
			'should throw when key size is too small for %s',
			algorithm => {
				const { publicKey: key } = generateKeyPairSync('rsa-pss', {
					modulusLength: rsaPssParams[algorithm].minKeyBits - 1
				})

				expect(() =>
					verifyRsaPss({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError.invalidSize(algorithm, 2048 / 8))
			}
		)
	})
})
