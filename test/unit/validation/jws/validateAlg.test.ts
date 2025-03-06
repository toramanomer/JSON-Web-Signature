import { describe, it, expect } from 'vitest'
import { validateAlg } from '../../../../src/validation/jws/validateAlg'
import { InvalidJWSHeaderParam } from '../../../../src/validation/jws/InvalidJWSHeaderParam'
import { algorithms } from '../../../../src/algorithms/algorithms'

describe('validateAlg', () => {
	describe('When alg is valid', () => {
		it.each(algorithms)('should accept %s as valid algorithm', alg => {
			const header = { alg }
			expect(() => validateAlg(header)).not.toThrow()
			expect(() => validateAlg(header, [alg])).not.toThrow()
		})
	})

	describe('When alg is invalid', () => {
		it('should throw when alg is missing', () => {
			const header = {}

			expect(() => validateAlg(header)).toThrow(
				new InvalidJWSHeaderParam(
					'The "alg" header parameter is required',
					'alg',
					'ALG_REQUIRED'
				)
			)
		})

		it('should throw when alg is not a supported algorithm', () => {
			const header = { alg: 'INVALID' }
			expect(() => validateAlg(header)).toThrow(
				new InvalidJWSHeaderParam(
					'Invalid algorithm: INVALID',
					'alg',
					'ALG_INVALID'
				)
			)
		})

		it('should throw when alg is undefined', () => {
			const header = { alg: undefined }

			expect(() => validateAlg(header)).toThrow(
				new InvalidJWSHeaderParam(
					'The "alg" header parameter is required',
					'alg',
					'ALG_REQUIRED'
				)
			)
		})

		it('should throw when alg is null', () => {
			const header = { alg: null }

			expect(() => validateAlg(header)).toThrow(
				new InvalidJWSHeaderParam(
					'The "alg" header parameter is required',
					'alg',
					'ALG_REQUIRED'
				)
			)
		})

		it('should throw when alg is not in allowedAlgorithms', () => {
			const header = { alg: 'HS256' }
			expect(() => validateAlg(header, ['HS384'])).toThrow(
				new InvalidJWSHeaderParam(
					'Invalid algorithm: HS256',
					'alg',
					'ALG_INVALID'
				)
			)
		})
	})
})
