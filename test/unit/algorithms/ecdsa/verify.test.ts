import { generateKeyPairSync, generateKeySync } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import { verifyEcdsa } from '../../../../src/algorithms/ecdsa/verify'
import { InvalidKeyError } from '../../../../src/algorithms/InvalidKeyError'
import {
	ecdsaParams,
	type EcdsaAlgorithm
} from '../../../../src/algorithms/ecdsa/params'

describe('verifyEcdsa', () => {
	describe('When using invalid key', () => {
		const algorithms = Object.keys(ecdsaParams) as EcdsaAlgorithm[]
		const signature = Buffer.from('dummy-signature')
		const signingInput = 'test'

		// Secret key
		it.for(algorithms)(
			'should throw when secret key is used with %s',
			algorithm => {
				const key = generateKeySync('hmac', { length: 256 })

				expect(() =>
					verifyEcdsa({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError)
			}
		)

		// Private key
		it.for(algorithms)(
			'should throw when private key is used with %s',
			algorithm => {
				const { privateKey: key } = generateKeyPairSync('ec', {
					namedCurve: ecdsaParams[algorithm].namedCurve
				})

				expect(() =>
					verifyEcdsa({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError)
			}
		)

		// Wrong asymmetric key type
		it.for(algorithms)(
			'should throw when RSA key is used with %s',
			algorithm => {
				const { publicKey: key } = generateKeyPairSync('rsa', {
					modulusLength: 2048
				})

				expect(() =>
					verifyEcdsa({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError)
			}
		)

		// Wrong curve
		it.for(algorithms)(
			'should throw when using wrong curve with %s',
			algorithm => {
				const [incorrectCurve] = Object.values(ecdsaParams)
					.map(param => param.namedCurve)
					.filter(
						curve => curve !== ecdsaParams[algorithm].namedCurve
					)

				const { publicKey: key } = generateKeyPairSync('ec', {
					namedCurve: incorrectCurve
				})

				expect(() =>
					verifyEcdsa({ algorithm, key, signature, signingInput })
				).toThrow(InvalidKeyError)
			}
		)
	})
})
