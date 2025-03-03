import { describe, it, expect } from 'vitest'
import { validateJwk } from '../../../../src/validation/jws/validateJwk'
import { InvalidJWSHeaderParam } from '../../../../src/validation/jws/InvalidJWSHeaderParam'
import { type JWSHeaderParameters } from '../../../../src/types/jws'

describe('validateJwk', () => {
	describe('Basic validation', () => {
		it('should accept headers without "jwk" parameter', () => {
			expect(() => validateJwk({ alg: 'HS256' } as any)).not.toThrow()
		})

		it('should throw if jwk is not a JSON object', () => {
			const error = new InvalidJWSHeaderParam(
				'The "jwk" header parameter must be a JSON object',
				'jwk',
				'JWK_NOT_OBJECT'
			)

			const invalidValues = [
				'string',
				123,
				true,
				[],
				null,
				undefined,
				Symbol(),
				BigInt(123)
			]

			invalidValues.forEach(value => {
				expect(() =>
					validateJwk({ jwk: value as any, alg: 'HS256' })
				).toThrow(error)
			})
		})

		it('should throw if jwk is missing kty parameter', () => {
			const error = new InvalidJWSHeaderParam(
				'JWK must contain a "kty" (Key Type) parameter',
				'jwk',
				'JWK_MISSING_KTY'
			)

			expect(() =>
				validateJwk({ jwk: { n: 'value', e: 'value' }, alg: 'RS256' })
			).toThrow(error)
		})

		it('should throw if kty is not a string', () => {
			const error = new InvalidJWSHeaderParam(
				'JWK must contain a "kty" (Key Type) parameter',
				'jwk',
				'JWK_MISSING_KTY'
			)

			const invalidValues = [123, true, [], {}, null]

			invalidValues.forEach(value => {
				expect(() =>
					validateJwk({ jwk: { kty: value as any }, alg: 'RS256' })
				).toThrow(error)
			})
		})
		it('should throw if kty is not a valid key type', () => {
			const error = new InvalidJWSHeaderParam(
				`Invalid key type. Must be one of: RSA, EC`,
				'jwk',
				'JWK_INVALID_KTY'
			)

			const invalidkeyTypes = ['oct', 'OKP', 'invalid']

			invalidkeyTypes.forEach(kty => {
				expect(() =>
					validateJwk({ jwk: { kty }, alg: 'RS256' })
				).toThrow(error)
			})
		})
	})

	describe('Key type and algorithm compatibility', () => {
		it('should throw for RSA algorithms with non-RSA key', () => {
			const rsaAlgorithms = [
				'RS256',
				'RS384',
				'RS512',
				'PS256',
				'PS384',
				'PS512'
			]

			rsaAlgorithms.forEach(alg => {
				const error = new InvalidJWSHeaderParam(
					`Algorithm ${alg} requires an RSA key (kty: "RSA"), but got "EC"`,
					'jwk',
					'JWK_WRONG_KEY_TYPE_FOR_ALG'
				)

				expect(() =>
					validateJwk({ jwk: { kty: 'EC' }, alg: alg as any })
				).toThrow(error)
			})
		})

		it('should throw for ECDSA algorithms with non-EC key', () => {
			const ecAlgorithms = ['ES256', 'ES384', 'ES512']

			ecAlgorithms.forEach(alg => {
				const error = new InvalidJWSHeaderParam(
					`Algorithm ${alg} requires an EC key (kty: "EC"), but got "RSA"`,
					'jwk',
					'JWK_WRONG_KEY_TYPE_FOR_ALG'
				)

				expect(() =>
					validateJwk({ jwk: { kty: 'RSA' }, alg: alg as any })
				).toThrow(error)
			})
		})
	})

	describe('EC key validation', () => {
		it('should throw if EC key is missing crv parameter', () => {
			const error = new InvalidJWSHeaderParam(
				'EC JWK must contain a "crv" (Curve) parameter',
				'jwk',
				'JWK_EC_MISSING_CRV'
			)

			expect(() =>
				validateJwk({
					jwk: { kty: 'EC', x: 'value', y: 'value' },
					alg: 'ES256'
				})
			).toThrow(error)
		})

		it('should throw if EC key has invalid curve', () => {
			const error = new InvalidJWSHeaderParam(
				'Invalid curve: invalid-curve. Must be one of: P-256, P-384, P-521',
				'jwk',
				'JWK_EC_INVALID_CURVE'
			)

			expect(() =>
				validateJwk({
					jwk: {
						kty: 'EC',
						crv: 'invalid-curve',
						x: 'value',
						y: 'value'
					},
					alg: 'ES256'
				})
			).toThrow(error)
		})

		it('should throw if EC key is missing x coordinate', () => {
			const error = new InvalidJWSHeaderParam(
				'EC JWK must contain an "x" coordinate parameter',
				'jwk',
				'JWK_EC_MISSING_X'
			)

			expect(() =>
				validateJwk({
					jwk: { kty: 'EC', crv: 'P-256', y: 'value' },
					alg: 'ES256'
				})
			).toThrow(error)
		})

		it('should throw if EC key is missing y coordinate', () => {
			const error = new InvalidJWSHeaderParam(
				'EC JWK must contain a "y" coordinate parameter',
				'jwk',
				'JWK_EC_MISSING_Y'
			)

			expect(() =>
				validateJwk({
					jwk: { kty: 'EC', crv: 'P-256', x: 'value' },
					alg: 'ES256'
				})
			).toThrow(error)
		})

		it('should accept valid EC key', () => {
			const validCurves = ['P-256', 'P-384', 'P-521']

			validCurves.forEach(curve => {
				expect(() =>
					validateJwk({
						jwk: { kty: 'EC', crv: curve, x: 'value', y: 'value' },
						alg: 'ES256'
					})
				).not.toThrow()
			})
		})

		it('should throw if EC key contains private key parameter', () => {
			const error = new InvalidJWSHeaderParam(
				`JWK contains private key parameters: d`,
				'jwk',
				'JWK_CONTAINS_PRIVATE_PARAMS'
			)

			expect(() =>
				validateJwk({
					jwk: {
						kty: 'EC',
						crv: 'P-256',
						x: 'value',
						y: 'value',
						d: 'value'
					},
					alg: 'ES256'
				})
			).toThrow(error)
		})
	})

	describe('RSA key validation', () => {
		it('should throw if RSA key is missing n parameter', () => {
			const error = new InvalidJWSHeaderParam(
				'RSA JWK must contain a "n" (modulus) parameter',
				'jwk',
				'JWK_RSA_MISSING_N'
			)

			expect(() =>
				validateJwk({ jwk: { kty: 'RSA', e: 'value' }, alg: 'RS256' })
			).toThrow(error)
		})

		it('should throw if RSA key is missing e parameter', () => {
			const error = new InvalidJWSHeaderParam(
				'RSA JWK must contain an "e" (exponent) parameter',
				'jwk',
				'JWK_RSA_MISSING_E'
			)

			expect(() =>
				validateJwk({ jwk: { kty: 'RSA', n: 'value' }, alg: 'RS256' })
			).toThrow(error)
		})

		it('should accept valid RSA key', () => {
			expect(() =>
				validateJwk({
					jwk: { kty: 'RSA', n: 'value', e: 'value' },
					alg: 'RS256'
				})
			).not.toThrow()
		})
	})

	describe('Private key parameter validation', () => {
		it('should throw if JWK contains private key parameters', () => {
			const privateParams = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth']

			privateParams.forEach(param => {
				const error = new InvalidJWSHeaderParam(
					`JWK contains private key parameters: ${param}`,
					'jwk',
					'JWK_CONTAINS_PRIVATE_PARAMS'
				)

				expect(() =>
					validateJwk({
						jwk: {
							kty: 'RSA',
							n: 'value',
							e: 'value',
							[param]: 'value'
						},
						alg: 'RS256'
					})
				).toThrow(error)
			})
		})

		it('should throw if JWK contains multiple private key parameters', () => {
			const error = new InvalidJWSHeaderParam(
				'JWK contains private key parameters: d, p',
				'jwk',
				'JWK_CONTAINS_PRIVATE_PARAMS'
			)

			expect(() =>
				validateJwk({
					jwk: {
						kty: 'RSA',
						n: 'value',
						e: 'value',
						d: 'value',
						p: 'value'
					},
					alg: 'RS256'
				})
			).toThrow(error)
		})
	})
})
