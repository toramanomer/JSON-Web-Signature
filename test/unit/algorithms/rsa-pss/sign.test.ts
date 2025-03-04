import { generateKeyPairSync, generateKeySync } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import { signRsaPss } from '../../../../src/algorithms/rsa-pss/sign'
import { InvalidKeyError } from '../../../../src/algorithms/InvalidKeyError'
import {
	rsaPssParams,
	type RsaPssAlgorithm
} from '../../../../src/algorithms/rsa-pss/params'

const signingInput = 'test'

describe('signRsaPss', () => {
	describe('When using invalid key', () => {
		const algorithms = Object.keys(rsaPssParams) as RsaPssAlgorithm[]

		// Secret key
		it.for(algorithms)(
			'should throw when secret key is used with %s',
			algorithm => {
				const key = generateKeySync('hmac', { length: 256 })

				expect(() =>
					signRsaPss({ algorithm, key, signingInput })
				).toThrow(InvalidKeyError.invalidType(algorithm, 'private'))
			}
		)

		// Public key
		it.for(algorithms)(
			'should throw when public key is used with %s',
			algorithm => {
				const { publicKey: key } = generateKeyPairSync('rsa-pss', {
					modulusLength: rsaPssParams[algorithm].minKeyBits
				})

				expect(() =>
					signRsaPss({ algorithm, key, signingInput })
				).toThrow(InvalidKeyError)
			}
		)

		// Wrong asymmetric key type
		it.for(algorithms)(
			'should throw when EC key is used with %s',
			algorithm => {
				const { privateKey: key } = generateKeyPairSync('ec', {
					namedCurve: 'P-256'
				})

				expect(() =>
					signRsaPss({ algorithm, key, signingInput })
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
				const { privateKey: key } = generateKeyPairSync('rsa-pss', {
					modulusLength: rsaPssParams[algorithm].minKeyBits - 1
				})

				expect(() =>
					signRsaPss({ algorithm, key, signingInput })
				).toThrow(InvalidKeyError.invalidSize(algorithm, 2048 / 8))
			}
		)
	})
})
