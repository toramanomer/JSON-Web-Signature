import { describe, it, expect } from 'vitest'
import { validateJku } from '../../../../src/validation/jws/validateJku'
import { InvalidJWSHeaderParam } from '../../../../src/validation/jws/InvalidJWSHeaderParam'

describe('validateJku', () => {
	it('should accept header without jku parameter', () => {
		expect(() => validateJku({})).not.toThrow()
		expect(() => validateJku({ alg: 'HS256' })).not.toThrow()
	})

	it('should throw for non-string jku values', () => {
		const error = new InvalidJWSHeaderParam(
			'The "jku" header parameter must be a string',
			'jku',
			'JKU_NOT_STRING'
		)

		expect(() => validateJku({ jku: 123 as any })).toThrow(error)
		expect(() => validateJku({ jku: true as any })).toThrow(error)
		expect(() => validateJku({ jku: {} as any })).toThrow(error)
		expect(() => validateJku({ jku: [] as any })).toThrow(error)
	})

	it('should throw for invalid URLs', () => {
		const error = new InvalidJWSHeaderParam(
			'The "jku" header parameter must be a valid URL',
			'jku',
			'JKU_INVALID_URL'
		)

		expect(() => validateJku({ jku: 'invalid-url' })).toThrow(error)
	})

	it('should throw for non-HTTPS URLs', () => {
		const error = new InvalidJWSHeaderParam(
			'The "jku" header parameter must use HTTPS scheme',
			'jku',
			'JKU_NOT_HTTPS'
		)

		expect(() => validateJku({ jku: 'http://example.com' })).toThrow(error)
	})

	it('should throw for URLs with fragments', () => {
		const error = new InvalidJWSHeaderParam(
			'The "jku" header parameter must not contain fragments',
			'jku',
			'JKU_CONTAINS_FRAGMENTS'
		)

		expect(() =>
			validateJku({ jku: 'https://example.com#fragment' })
		).toThrow(error)
	})

	it('should throw for URLs with query parameters', () => {
		const error = new InvalidJWSHeaderParam(
			'The "jku" header parameter must not contain query parameters',
			'jku',
			'JKU_CONTAINS_QUERY_PARAMS'
		)

		expect(() =>
			validateJku({ jku: 'https://example.com?param=value' })
		).toThrow(error)
	})
})
