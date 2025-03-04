import { generateKeyPairSync, generateKeySync } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import { signHmac } from '../../../../src/algorithms/hmac/sign'
import { InvalidKeyError } from '../../../../src/algorithms/InvalidKeyError'
import {
	hmacParams,
	type HmacAlgorithm
} from '../../../../src/algorithms/hmac/params'

const signingInput = 'test'

describe('signHmac', () => {
	describe('When using invalid key', () => {
		const algorithms = Object.keys(hmacParams) as HmacAlgorithm[]

		// Private key
		it.for(algorithms)(
			'should throw when private key is used with %s',
			algorithm => {
				const { privateKey: key } = generateKeyPairSync('rsa', {
					modulusLength: 2048
				})

				expect(() =>
					signHmac({ algorithm, key, signingInput })
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
					signHmac({ algorithm, key, signingInput })
				).toThrow(InvalidKeyError.invalidType(algorithm, 'secret'))
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
					signHmac({ algorithm, key, signingInput })
				).toThrow(InvalidKeyError.invalidSize(algorithm, minBytes))
			}
		)
	})
})
