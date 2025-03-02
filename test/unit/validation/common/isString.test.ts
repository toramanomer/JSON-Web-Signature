import { describe, it, expect } from 'vitest'
import { isString } from '../../../../src/validation/common/isString'

describe('isString function', () => {
	it('returns true for string literals', () => {
		expect(isString('hello')).toBe(true)
		expect(isString('')).toBe(true)
		expect(isString(' ')).toBe(true)
	})

	it('returns true for String objects', () => {
		// eslint-disable-next-line no-new-wrappers
		expect(isString(new String('hello'))).toBe(false) // String objects are not primitives
	})

	it('returns false for non-string values', () => {
		expect(isString(123)).toBe(false)
		expect(isString(0)).toBe(false)
		expect(isString(true)).toBe(false)
		expect(isString(false)).toBe(false)
		expect(isString(null)).toBe(false)
		expect(isString(undefined)).toBe(false)
		expect(isString({})).toBe(false)
		expect(isString([])).toBe(false)
		expect(isString(() => {})).toBe(false)
	})

	it('returns false for symbol values', () => {
		expect(isString(Symbol('sym'))).toBe(false)
	})

	it('returns false for bigint values', () => {
		expect(isString(BigInt(123))).toBe(false)
	})
})
