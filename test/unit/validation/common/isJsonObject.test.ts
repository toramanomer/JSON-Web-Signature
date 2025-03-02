import { describe, it, expect } from 'vitest'
import { isJsonObject } from '../../../../src/validation/common/isJsonObject'

describe.only('isJsonObject function', () => {
	describe('Non-object values', () => {
		it('When invoked with undefined, it must return false', () => {
			expect(isJsonObject(undefined)).toBe(false)
		})

		it('When invoked with null, it must return false', () => {
			expect(isJsonObject(null)).toBe(false)
		})

		it('When invoked with a boolean, it must return false', () => {
			const bools = [true, false, Boolean(), new Boolean()]
			bools.forEach(value => {
				expect(isJsonObject(value)).toBe(false)
			})
		})

		it('When invoked with a number, it must return false', () => {
			const numbers = [
				-Infinity,
				-1,
				-0,
				0,
				+0,
				1,
				Infinity,
				NaN,
				Number(),
				new Number(),
				Number.MAX_SAFE_INTEGER,
				Number.MIN_SAFE_INTEGER,
				-1.5,
				1.5
			]
			numbers.forEach(value => {
				expect(isJsonObject(value)).toBe(false)
			})
		})

		it('When invoked with a string, it must return false', () => {
			const strings = ['', String(), new String(), '{}']
			strings.forEach(value => {
				expect(isJsonObject(value)).toBe(false)
			})
		})

		it('When invoked with a symbol, it must return false', () => {
			const symbols = [Symbol(), Symbol('symbol'), Symbol.for('symbol')]
			symbols.forEach(value => {
				expect(isJsonObject(value)).toBe(false)
			})
		})

		it('When invoked with a bigint, it must return false', () => {
			const bigints = [BigInt(1), BigInt(Number.MAX_SAFE_INTEGER), 1n]
			bigints.forEach(value => {
				expect(isJsonObject(value)).toBe(false)
			})
		})

		it('When invoked with a function or class, it must return false', () => {
			const functions = [function () {}, () => {}, class {}, class Foo {}]
			functions.forEach(value => {
				expect(isJsonObject(value)).toBe(false)
			})
		})

		it('When invoked with an array, it must return false', () => {
			const arrays = [[], Array(), new Array(), [1], ['a'], [{}]]
			arrays.forEach(value => {
				expect(isJsonObject(value)).toBe(false)
			})
		})

		it('When invoked with objects with custom prototypes, it must return false', () => {
			const customPrototypes = [
				new Map([['key', 'value']]),
				new Set([1, 2, 3]),
				new Error('error'),
				Promise.resolve(),
				new RegExp('pattern'),
				new WeakSet(),
				new WeakMap(),
				/regex/,
				new Date(),
				new (class {})(),
				new (class Foo {})(),
				Object.create(
					{ parentKey: 'value' },
					{ childKey: { value: 'value', enumerable: true } }
				),
				Object.create(null, {
					key: { value: 'value', enumerable: true }
				})
			]
			customPrototypes.forEach(value => {
				expect(isJsonObject(value)).toBe(false)
			})
		})
	})

	describe('Objects with invalid values', () => {
		it('When invoked with objects containing invalid values, it must return false', () => {
			const objects = [
				{ key: undefined },
				{ key: () => {} },
				{ key: Symbol('test') },
				{ key: BigInt(123) },
				{ key: NaN },
				{ key: Infinity },
				{ key: -Infinity },
				{ key: new Date() },
				{ key: /test/ },
				{ key: new Map() },
				{ key: new Set() },
				{ key: new Error('test') },
				{ key: new (class A {})() }
			]
			objects.forEach(obj => {
				expect(isJsonObject(obj)).toBe(false)
			})
		})

		it('When invoked with nested objects containing invalid values, it must return false', () => {
			const objects = [
				{ nested: { key: undefined } },
				{ nested: { key: () => {} } },
				{ nested: { key: Symbol('test') } },
				{ nested: { key: BigInt(123) } },
				{ nested: { key: NaN } },
				{ nested: { key: Infinity } },
				{ nested: { key: -Infinity } },
				{ nested: { key: new Date() } },
				{ nested: { key: /test/ } },
				{ nested: { key: new Map() } },
				{ nested: { key: new Set() } },
				{ nested: { key: new Error('test') } },
				{ nested: { key: new (class A {})() } }
			]
			objects.forEach(obj => {
				expect(isJsonObject(obj)).toBe(false)
			})
		})

		it('When invoked with objects containing invalid values in arrays, it must return false', () => {
			const objects = [
				{ key: [1, 2, { key: undefined }] },
				{ key: [1, 2, { nested: { key: undefined } }] },

				{ key: [1, 2, { key: () => {} }] },
				{ key: [1, 2, { nested: { key: () => {} } }] },

				{ key: [1, 2, { key: Symbol('test') }] },
				{ key: [1, 2, { nested: { key: Symbol('test') } }] },

				{ key: [1, 2, { key: BigInt(123) }] },
				{ key: [1, 2, { nested: { key: BigInt(123) } }] },

				{ key: [1, 2, { key: NaN }] },
				{ key: [1, 2, { nested: { key: NaN } }] },

				{ key: [1, 2, { key: Infinity }] },
				{ key: [1, 2, { nested: { key: Infinity } }] },

				{ key: [1, 2, { key: -Infinity }] },
				{ key: [1, 2, { nested: { key: -Infinity } }] },

				{ key: [1, 2, { key: new Date() }] },
				{ key: [1, 2, { nested: { key: new Date() } }] },

				{ key: [1, 2, { key: /test/ }] },
				{ key: [1, 2, { nested: { key: /test/ } }] },

				{ key: [1, 2, { key: new Map() }] },
				{ key: [1, 2, { nested: { key: new Map() } }] },

				{ key: [1, 2, { key: new Set() }] },
				{ key: [1, 2, { nested: { key: new Set() } }] },

				{ key: [1, 2, { key: new Error('test') }] },
				{ key: [1, 2, { nested: { key: new Error('test') } }] },

				{ key: [1, 2, { key: new (class A {})() }] },
				{ key: [1, 2, { nested: { key: new (class A {})() } }] }
			]

			objects.forEach(obj => {
				expect(isJsonObject(obj)).toBe(false)
			})
		})
	})

	describe('Valid JSON objects', () => {
		it('Empty object should be valid', () => {
			expect(isJsonObject({})).toBe(true)
		})

		describe('Primitive value properties', () => {
			it('Object with string values should be valid', () => {
				expect(isJsonObject({ key: 'value' })).toBe(true)
			})

			it('Object with number values should be valid', () => {
				expect(isJsonObject({ key: 42 })).toBe(true)
			})

			it('Object with boolean values should be valid', () => {
				expect(isJsonObject({ key: true })).toBe(true)
			})

			it('Object with null values should be valid', () => {
				expect(isJsonObject({ key: null })).toBe(true)
			})

			it('Object with mixed primitive values should be valid', () => {
				expect(
					isJsonObject({ string: 'value', number: 42, boolean: true })
				).toBe(true)
			})
		})

		describe('Array value properties', () => {
			it('Object with array values should be valid', () => {
				expect(isJsonObject({ key: [1, 2, 3] })).toBe(true)
			})
		})

		describe('Nested objects', () => {
			it('Object with nested object values should be valid', () => {
				expect(isJsonObject({ nested: { key: 'value' } })).toBe(true)
			})

			it('Complex nested structure with various valid types should be valid', () => {
				expect(
					isJsonObject({
						key: 'value',
						nested: { key: 42 },
						deeplyNested: { key: true, nested: { key: null } }
					})
				).toBe(true)
			})
		})
	})
})
