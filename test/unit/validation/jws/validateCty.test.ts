import { describe, it, expect } from 'vitest'
import { validateCty } from '../../../../src/validation/jws/validateCty'
import { InvalidJWSHeaderParam } from '../../../../src/validation/jws/InvalidJWSHeaderParam'

describe('validateCty', () => {
	it('should accept header without cty parameter', () => {
		expect(() => validateCty({})).not.toThrow()
		expect(() => validateCty({ alg: 'HS256' })).not.toThrow()
	})

	it('should accept valid string values for cty', () => {
		expect(() => validateCty({ cty: 'JWT' })).not.toThrow()
		expect(() => validateCty({ cty: 'JOSE' })).not.toThrow()
		expect(() => validateCty({ cty: 'application/jwt' })).not.toThrow()
		expect(() => validateCty({ cty: '' })).not.toThrow()
	})

	it('should throw for non-string cty values', () => {
		const error = new InvalidJWSHeaderParam(
			'The "cty" header parameter must be a string',
			'cty',
			'CTY_NOT_STRING'
		)

		expect(() => validateCty({ cty: 123 as any })).toThrow(error)
		expect(() => validateCty({ cty: true as any })).toThrow(error)
		expect(() => validateCty({ cty: {} as any })).toThrow(error)
		expect(() => validateCty({ cty: [] as any })).toThrow(error)
		expect(() => validateCty({ cty: null as any })).toThrow(error)
		expect(() => validateCty({ cty: undefined as any })).toThrow(error)
		expect(() => validateCty({ cty: Symbol() as any })).toThrow(error)
		expect(() => validateCty({ cty: BigInt(123) as any })).toThrow(error)
	})

	it('should preserve error properties when throwing', () => {
		try {
			validateCty({ cty: 123 as any })
			expect.fail('Should have thrown an error')
		} catch (error) {
			expect(error).toBeInstanceOf(InvalidJWSHeaderParam)
			expect(error.message).toBe(
				'The "cty" header parameter must be a string'
			)
			expect(error.headerParameter).toBe('cty')
			expect(error.code).toBe('CTY_NOT_STRING')
		}
	})
})
