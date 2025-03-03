import { describe, it, expect } from 'vitest'
import { validateKid } from '../../../../src/validation/jws/validateKid'
import { InvalidJWSHeaderParam } from '../../../../src/validation/jws/InvalidJWSHeaderParam'

describe('validateKid', () => {
	it('should accept header without kid parameter', () => {
		expect(() => validateKid({})).not.toThrow()
		expect(() => validateKid({ alg: 'HS256' })).not.toThrow()
	})

	it('should throw for non-string kid values', () => {
		const error = new InvalidJWSHeaderParam(
			'The "kid" header parameter must be a string',
			'kid',
			'KID_NOT_STRING'
		)

		expect(() => validateKid({ kid: 123 as any })).toThrow(error)
		expect(() => validateKid({ kid: true as any })).toThrow(error)
		expect(() => validateKid({ kid: {} as any })).toThrow(error)
		expect(() => validateKid({ kid: [] as any })).toThrow(error)
		expect(() => validateKid({ kid: null as any })).toThrow(error)
		expect(() => validateKid({ kid: undefined as any })).toThrow(error)
		expect(() => validateKid({ kid: Symbol() as any })).toThrow(error)
		expect(() => validateKid({ kid: BigInt(123) as any })).toThrow(error)
	})

	it('should throw for empty kid values', () => {
		const error = new InvalidJWSHeaderParam(
			'The "kid" header parameter must not be empty',
			'kid',
			'KID_EMPTY'
		)

		expect(() => validateKid({ kid: '' })).toThrow(error)
		expect(() => validateKid({ kid: '   ' })).toThrow(error)
		expect(() => validateKid({ kid: '\n' })).toThrow(error)
		expect(() => validateKid({ kid: '\t' })).toThrow(error)
		expect(() => validateKid({ kid: '\r' })).toThrow(error)
		expect(() => validateKid({ kid: '\f' })).toThrow(error)
		expect(() => validateKid({ kid: '\v' })).toThrow(error)
	})
})
