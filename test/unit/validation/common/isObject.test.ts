import { describe, it, expect } from 'vitest'
import { isObject } from '../../../../src/validation/common/isObject'

describe('isObject', () => {
	it('should return true for plain objects', () => {
		expect(isObject({})).toBe(true)
		expect(isObject({ key: 'value' })).toBe(true)
	})

	it('should return false for arrays', () => {
		expect(isObject([])).toBe(false)
		expect(isObject(['value'])).toBe(false)
	})

	it('should return false for null', () => {
		expect(isObject(null)).toBe(false)
	})

	it('should return false for primitives', () => {
		expect(isObject(42)).toBe(false)
		expect(isObject('string')).toBe(false)
		expect(isObject(true)).toBe(false)
		expect(isObject(undefined)).toBe(false)
		expect(isObject(Symbol())).toBe(false)
		expect(isObject(BigInt(42))).toBe(false)
	})
})
