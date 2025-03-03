import { describe, it, expect } from 'vitest'
import { validateCrit } from '../../../../src/validation/jws/validateCrit'
import { InvalidJWSHeaderParam } from '../../../../src/validation/jws/InvalidJWSHeaderParam'

describe('validateCrit', () => {
	describe('Basic validation', () => {
		it('should accept headers without "crit" parameter', () => {
			expect(() =>
				validateCrit({
					protectedHeader: { alg: 'HS256' },
					unprotectedHeader: { kid: 'key-1' }
				})
			).not.toThrow()
		})
	})

	describe('Unprotected header validation', () => {
		it('should throw if "crit" is in unprotected header', () => {
			const error = new InvalidJWSHeaderParam(
				'The "crit" header parameter must not be in the unprotected header',
				'crit',
				'CRIT_IN_UNPROTECTED'
			)

			const values = [null, undefined, ['custom-param']]

			values.forEach(value => {
				expect(() =>
					validateCrit({
						protectedHeader: { alg: 'HS256' },
						unprotectedHeader: { crit: value as any }
					})
				).toThrow(error)

				expect(() =>
					validateCrit({
						protectedHeader: {
							alg: 'HS256',
							crit: ['custom-param']
						},
						unprotectedHeader: { crit: value as any }
					})
				).toThrow(error)
			})
		})
	})

	describe('Array validation', () => {
		it('should throw if "crit" is not an array', () => {
			const error = new InvalidJWSHeaderParam(
				'The "crit" header parameter must be an array of strings',
				'crit',
				'CRIT_NOT_ARRAY'
			)

			const invalidValues = [
				'string',
				123,
				true,
				{},
				null,
				undefined,
				Symbol(),
				BigInt(123)
			]

			invalidValues.forEach(value => {
				expect(() =>
					validateCrit({ protectedHeader: { crit: value as any } })
				).toThrow(error)
			})
		})

		it('should throw if crit array is empty', () => {
			const error = new InvalidJWSHeaderParam(
				'The "crit" header parameter must not be empty',
				'crit',
				'CRIT_EMPTY'
			)

			expect(() =>
				validateCrit({ protectedHeader: { crit: [] } })
			).toThrow(error)
		})
	})

	describe('Array entries validation', () => {
		it('should throw if "crit" contains non-string values', () => {
			const error = new InvalidJWSHeaderParam(
				'The "crit" header parameter must contain only strings',
				'crit',
				'CRIT_INVALID_ENTRIES'
			)

			const invalidEntries = [
				[123],
				[true],
				[{}],
				[[]],
				[null],
				[undefined],
				[Symbol()],
				[BigInt(123)],
				['valid', 123],
				['valid', null],
				['valid', undefined]
			]

			invalidEntries.forEach(entries => {
				expect(() =>
					validateCrit({ protectedHeader: { crit: entries as any } })
				).toThrow(error)
			})
		})

		it('should throw if "crit" contains empty strings', () => {
			const error = new InvalidJWSHeaderParam(
				'The "crit" header parameter must contain only strings',
				'crit',
				'CRIT_INVALID_ENTRIES'
			)

			expect(() =>
				validateCrit({ protectedHeader: { crit: [''] } })
			).toThrow(error)

			expect(() =>
				validateCrit({ protectedHeader: { crit: ['valid', ''] } })
			).toThrow(error)
		})
	})

	describe('Registered parameter validation', () => {
		it('should throw if "crit" contains registered header parameters', () => {
			const registeredParams = [
				'alg',
				'jku',
				'jwk',
				'kid',
				'x5u',
				'x5c',
				'x5t',
				'x5t#S256',
				'typ',
				'cty',
				'crit'
			]

			registeredParams.forEach(param => {
				const error = new InvalidJWSHeaderParam(
					`The "crit" header parameter must not contain registered header parameter names: ${param}`,
					'crit',
					'CRIT_REGISTERED_PARAMS'
				)

				expect(() =>
					validateCrit({ protectedHeader: { crit: [param] } })
				).toThrow(error)

				expect(() =>
					validateCrit({
						protectedHeader: { crit: ['custom-param', param] }
					})
				).toThrow(error)
			})
		})
	})

	describe('Duplicate values validation', () => {
		it('should throw if "crit" contains duplicate values', () => {
			const error = new InvalidJWSHeaderParam(
				'The "crit" header parameter must not contain duplicate values',
				'crit',
				'CRIT_DUPLICATE_VALUES'
			)

			expect(() =>
				validateCrit({
					protectedHeader: { crit: ['custom-param', 'custom-param'] }
				})
			).toThrow(error)

			expect(() =>
				validateCrit({
					protectedHeader: {
						crit: ['custom-1', 'custom-2', 'custom-1']
					}
				})
			).toThrow(error)
		})
	})

	describe('Missing parameters validation', () => {
		it('should throw if crit references parameters not present in headers', () => {
			const error = new InvalidJWSHeaderParam(
				'The header parameters custom-param are not present in the JWS header, but are present in the "crit" header parameter',
				'crit',
				'CRIT_MISSING_PARAMS'
			)

			expect(() =>
				validateCrit({ protectedHeader: { crit: ['custom-param'] } })
			).toThrow(error)
		})

		it('should accept when all referenced parameters are present', () => {
			expect(() =>
				validateCrit({
					protectedHeader: {
						'crit': ['custom-param'],
						'custom-param': 'value'
					}
				})
			).not.toThrow()

			expect(() =>
				validateCrit({
					protectedHeader: {
						'crit': ['custom-1', 'custom-2'],
						'custom-1': 'value1',
						'custom-2': 'value2'
					}
				})
			).not.toThrow()
		})

		it('should accept when referenced parameters are in unprotected header', () => {
			expect(() =>
				validateCrit({
					protectedHeader: { crit: ['custom-param'] },
					unprotectedHeader: { 'custom-param': 'value' }
				})
			).not.toThrow()
		})

		it('should accept when referenced parameters are split between headers', () => {
			expect(() =>
				validateCrit({
					protectedHeader: {
						'crit': ['custom-1', 'custom-2'],
						'custom-1': 'value1'
					},
					unprotectedHeader: { 'custom-2': 'value2' }
				})
			).not.toThrow()
		})
	})
})
