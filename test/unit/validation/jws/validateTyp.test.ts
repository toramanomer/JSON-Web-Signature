import { describe, it, expect } from 'vitest'
import { validateTyp } from '../../../../src/validation/jws/validateTyp'
import { InvalidJWSHeaderParam } from '../../../../src/validation/jws/InvalidJWSHeaderParam'

describe('validateTyp', () => {
	it('should accept header without typ parameter', () => {
		expect(() => validateTyp({})).not.toThrow()
		expect(() => validateTyp({ alg: 'HS256' })).not.toThrow()
	})

	it('should accept valid string values for typ', () => {
		expect(() => validateTyp({ typ: 'JWT' })).not.toThrow()
		expect(() => validateTyp({ typ: 'JOSE' })).not.toThrow()
		expect(() => validateTyp({ typ: 'application/jwt' })).not.toThrow()
		expect(() => validateTyp({ typ: '' })).not.toThrow()
	})

	it('should throw for non-string typ values', () => {
		const error = new InvalidJWSHeaderParam(
			'The "typ" header parameter must be a string',
			'typ',
			'TYP_NOT_STRING'
		)

		expect(() => validateTyp({ typ: 123 as any })).toThrow(error)
		expect(() => validateTyp({ typ: true as any })).toThrow(error)
		expect(() => validateTyp({ typ: {} as any })).toThrow(error)
		expect(() => validateTyp({ typ: [] as any })).toThrow(error)
		expect(() => validateTyp({ typ: null as any })).toThrow(error)
		expect(() => validateTyp({ typ: undefined as any })).toThrow(error)
		expect(() => validateTyp({ typ: Symbol() as any })).toThrow(error)
		expect(() => validateTyp({ typ: BigInt(123) as any })).toThrow(error)
	})

	it('should preserve error properties when throwing', () => {
		try {
			validateTyp({ typ: 123 as any })
			expect.fail('Should have thrown an error')
		} catch (error) {
			expect(error).toBeInstanceOf(InvalidJWSHeaderParam)
			expect(error.message).toBe(
				'The "typ" header parameter must be a string'
			)
			expect(error.headerParameter).toBe('typ')
			expect(error.code).toBe('TYP_NOT_STRING')
		}
	})
})
