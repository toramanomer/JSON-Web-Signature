import { describe, it, expect } from 'vitest'
import {
	base64UrlEncode,
	base64UrlDecode,
	isBase64url
} from '../../../src/encoding/base64url'

describe('base64url', () => {
	const vectors = [
		{ input: '', expected: '' },
		{ input: 'f', expected: 'Zg' },
		{ input: 'fo', expected: 'Zm8' },
		{ input: 'foo', expected: 'Zm9v' },
		{ input: 'foob', expected: 'Zm9vYg' },
		{ input: 'fooba', expected: 'Zm9vYmE' },
		{ input: 'foobar', expected: 'Zm9vYmFy' }
	]

	vectors.forEach(({ input, expected }) => {
		it(`should encode ${input} to ${expected}`, () => {
			expect(base64UrlEncode(input)).toBe(expected)
		})

		it(`should decode ${expected} to ${input}`, () => {
			expect(base64UrlDecode(expected).toString()).toBe(input)
		})

		it(`should check if ${expected} is base64url encoded`, () => {
			expect(isBase64url(expected)).toBe(true)
		})
	})

	const invalidBase64urlStrings = [' ', '-', '==', '/']

	invalidBase64urlStrings.forEach(input => {
		it(`should check if ${input} is not base64url encoded`, () => {
			expect(isBase64url(input)).toBe(false)
		})
	})
})
