import { describe, it, expect } from 'vitest'
import { isDisjoint } from '../../../../src/validation/common/isDisjoint'

describe('isDisjoint function', () => {
	describe('Null or undefined inputs', () => {
		it('When protectedHeader is undefined and unprotectedHeader is defined, it must return true', () => {
			const unprotectedHeader = { alg: 'HS256', kid: 'key-1' }
			expect(isDisjoint(undefined, unprotectedHeader)).toBe(true)
		})

		it('When protectedHeader is defined and unprotectedHeader is undefined, it must return true', () => {
			const protectedHeader = { alg: 'HS256', kid: 'key-1' }
			expect(isDisjoint(protectedHeader, undefined)).toBe(true)
		})

		it('When protectedHeader is null and unprotectedHeader is defined, it must return true', () => {
			const unprotectedHeader = { alg: 'HS256', kid: 'key-1' }
			expect(isDisjoint(null as any, unprotectedHeader)).toBe(true)
		})

		it('When protectedHeader is defined and unprotectedHeader is null, it must return true', () => {
			const protectedHeader = { alg: 'HS256', kid: 'key-1' }
			expect(isDisjoint(protectedHeader, null as any)).toBe(true)
		})
	})

	describe('Empty objects', () => {
		it('When protectedHeader is empty and unprotectedHeader has properties, it must return true', () => {
			const unprotectedHeader = { alg: 'HS256', kid: 'key-1' }
			expect(isDisjoint({}, unprotectedHeader)).toBe(true)
		})

		it('When protectedHeader has properties and unprotectedHeader is empty, it must return true', () => {
			const protectedHeader = { alg: 'HS256', kid: 'key-1' }
			expect(isDisjoint(protectedHeader, {})).toBe(true)
		})
	})

	describe('Disjoint headers', () => {
		it('When headers have completely different properties, it must return true', () => {
			const protectedHeader = { alg: 'HS256', kid: 'key-1' }
			const unprotectedHeader = {
				cty: 'JWT',
				jku: 'https://example.com/keys'
			}
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(true)
		})

		it('When headers have many different properties, it must return true', () => {
			const protectedHeader = {
				alg: 'HS256',
				kid: 'key-1',
				typ: 'JWT',
				crit: ['exp', 'nbf']
			}
			const unprotectedHeader = {
				jku: 'https://example.com/keys',
				x5u: 'https://example.com/cert',
				x5c: ['base64cert'],
				x5t: 'thumbprint'
			}
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(true)
		})

		it('When headers have properties with similar values but different names, it must return true', () => {
			const protectedHeader = { alg: 'HS256', kid: 'key-1' }
			const unprotectedHeader = { algorithm: 'HS256', keyId: 'key-1' }
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(true)
		})

		it('When headers have properties with different case in names, it must return true', () => {
			const protectedHeader = { alg: 'HS256', kid: 'key-1' }
			const unprotectedHeader = { ALG: 'RS256', KID: 'key-2' }
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(true)
		})
	})

	describe('Non-disjoint headers', () => {
		it('When headers share one common property, it must return false', () => {
			const protectedHeader = { alg: 'HS256', kid: 'key-1' }
			const unprotectedHeader = { alg: 'RS256', cty: 'JWT' }
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(false)
		})

		it('When headers share multiple common properties, it must return false', () => {
			const protectedHeader = { alg: 'HS256', kid: 'key-1', typ: 'JWT' }
			const unprotectedHeader = { alg: 'RS256', kid: 'key-2', typ: 'JWS' }
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(false)
		})

		it('When all properties from one header exist in the other, it must return false', () => {
			const protectedHeader = { alg: 'HS256', kid: 'key-1' }
			const unprotectedHeader = {
				alg: 'RS256',
				kid: 'key-2',
				cty: 'JWT',
				jku: 'https://example.com/keys'
			}
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(false)
		})

		it('When headers are identical, it must return false', () => {
			const protectedHeader = { alg: 'HS256', kid: 'key-1' }
			const unprotectedHeader = { alg: 'HS256', kid: 'key-1' }
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(false)
		})
	})

	describe('Edge cases', () => {
		it('When headers have empty string keys, it should handle them correctly', () => {
			const protectedHeader = { '': 'empty-key' }
			const unprotectedHeader = { '': 'different-value' }
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(false)
		})

		it('When headers have numeric keys as strings, it should handle them correctly', () => {
			const protectedHeader = { '1': 'numeric-key' }
			const unprotectedHeader = { '2': 'another-numeric-key' }
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(true)
		})

		it('When headers have the same numeric keys as strings, it should detect them as common', () => {
			const protectedHeader = { '1': 'numeric-key' }
			const unprotectedHeader = { '1': 'different-value' }
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(false)
		})

		it('When headers have keys with special characters, it should handle them correctly', () => {
			const protectedHeader = { 'x-key!@#': 'special-chars' }
			const unprotectedHeader = { 'y-key!@#': 'more-special-chars' }
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(true)
		})

		it('When headers have symbols that look similar but are different unicode characters, it should handle them correctly', () => {
			// These look similar but are different Unicode characters
			const protectedHeader = { кey: 'cyrillic-k' } // Cyrillic 'к'
			const unprotectedHeader = { key: 'latin-k' } // Latin 'k'
			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(true)
		})
	})

	describe('JWS header examples', () => {
		it('When using standard JWS header parameters in a disjoint way, it must return true', () => {
			// Protected header typically contains critical security parameters
			const protectedHeader = {
				alg: 'RS256',
				kid: 'key-1',
				typ: 'JWT',
				crit: ['exp']
			}

			// Unprotected header contains non-critical parameters
			const unprotectedHeader = {
				jku: 'https://example.com/keys',
				x5u: 'https://example.com/cert'
			}

			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(true)
		})

		it('When using standard JWS header parameters in a non-disjoint way, it must return false', () => {
			const protectedHeader = { alg: 'RS256', kid: 'key-1' }

			const unprotectedHeader = {
				alg: 'none',
				jku: 'https://example.com/keys'
			}

			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(false)
		})

		it('When using typical JOSE header parameters, it must handle them correctly', () => {
			const protectedHeader = { alg: 'ES256', b64: true, crit: ['b64'] }

			const unprotectedHeader = {
				cty: 'application/example',
				kid: '1234567890'
			}

			expect(isDisjoint(protectedHeader, unprotectedHeader)).toBe(true)
		})
	})
})
