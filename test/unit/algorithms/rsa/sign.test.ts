import { generateKeyPairSync, generateKeySync } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import { signRsa } from '../../../../src/algorithms/rsa/sign'
import { InvalidKeyError } from '../../../../src/algorithms/InvalidKeyError'
import {
	rsaParams,
	type RsaAlgorithm
} from '../../../../src/algorithms/rsa/params'

const signingInput = 'test'

describe('signRsa', () => {
	describe('When using invalid key', () => {
		const algorithms = Object.keys(rsaParams) as RsaAlgorithm[]

		// Secret key
		it.for(algorithms)(
			'should throw when secret key is used with %s',
			algorithm => {
				const key = generateKeySync('hmac', { length: 256 })

				expect(() => signRsa({ algorithm, key, signingInput })).toThrow(
					InvalidKeyError.invalidType(algorithm, 'private')
				)
			}
		)

		// Public key
		it.for(algorithms)(
			'should throw when public key is used with %s',
			algorithm => {
				const { publicKey: key } = generateKeyPairSync('rsa', {
					modulusLength: rsaParams[algorithm].minKeyBits
				})

				expect(() => signRsa({ algorithm, key, signingInput })).toThrow(
					InvalidKeyError.invalidType(algorithm, 'private')
				)
			}
		)

		// Wrong asymmetric key type
		it.for(algorithms)(
			'should throw when EC key is used with %s',
			algorithm => {
				const { privateKey: key } = generateKeyPairSync('ec', {
					namedCurve: 'P-256'
				})

				expect(() => signRsa({ algorithm, key, signingInput })).toThrow(
					InvalidKeyError.invalidAsymmetricKeyType(algorithm, 'rsa')
				)
			}
		)

		// Key too small
		it.for(algorithms)(
			'should throw when key size is too small for %s',
			algorithm => {
				const { privateKey: key } = generateKeyPairSync('rsa', {
					modulusLength: rsaParams[algorithm].minKeyBits - 1
				})

				expect(() => signRsa({ algorithm, key, signingInput })).toThrow(
					InvalidKeyError.invalidSize(algorithm, 2048 / 8)
				)
			}
		)
	})
})
