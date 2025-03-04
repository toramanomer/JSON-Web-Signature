import { generateKeyPairSync, generateKeySync } from 'node:crypto'
import { describe, it, expect } from 'vitest'

import { signEcdsa } from '../../../../src/algorithms/ecdsa/sign'
import { InvalidKeyError } from '../../../../src/algorithms/InvalidKeyError'
import {
	ecdsaParams,
	type EcdsaAlgorithm
} from '../../../../src/algorithms/ecdsa/params'

const signingInput = 'test'

describe('signEcdsa', () => {
	describe('When using invalid key', () => {
		const algorithms = Object.keys(ecdsaParams) as EcdsaAlgorithm[]

		// Secret key
		it.for(algorithms)(
			'should throw when secret key is used with %s',
			algorithm => {
				const key = generateKeySync('aes', { length: 256 })

				expect(() =>
					signEcdsa({ algorithm, key, signingInput })
				).toThrow(InvalidKeyError.invalidType(algorithm, 'private'))
			}
		)

		// Public key
		it.for(algorithms)(
			'should throw when public key is used with %s',
			algorithm => {
				const { publicKey: key } = generateKeyPairSync('ec', {
					namedCurve: ecdsaParams[algorithm].namedCurve
				})

				expect(() =>
					signEcdsa({ algorithm, key, signingInput })
				).toThrow(InvalidKeyError.invalidType(algorithm, 'private'))
			}
		)

		// Incorrect asymmetric key type
		it.for(algorithms)(
			'should throw when using wrong asymmetric key type with %s',
			algorithm => {
				const { privateKey: key } = generateKeyPairSync('rsa', {
					modulusLength: 2048
				})

				expect(() =>
					signEcdsa({ algorithm, key, signingInput })
				).toThrow(
					InvalidKeyError.invalidAsymmetricKeyType(algorithm, 'ec')
				)
			}
		)

		// Incorrect curve
		it.for(algorithms)(
			'should throw when using wrong curve with %s',
			algorithm => {
				const [inCorrectCurve] = Object.values(ecdsaParams)
					.map(param => param.namedCurve)
					.filter(
						curve => curve !== ecdsaParams[algorithm].namedCurve
					)

				const { privateKey: key } = generateKeyPairSync('ec', {
					namedCurve: inCorrectCurve
				})

				expect(() =>
					signEcdsa({ algorithm, key, signingInput })
				).toThrow(InvalidKeyError.invalidCurve(algorithm))
			}
		)
	})
})
