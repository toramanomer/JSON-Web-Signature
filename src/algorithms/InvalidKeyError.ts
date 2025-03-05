import type { KeyObjectType, KeyType } from 'node:crypto'
import type { Algorithm } from './algorithms.js'

const invalidKeyCodes = {
	INVALID_KEY_TYPE: 'INVALID_KEY_TYPE',
	INVALID_KEY_SIZE: 'INVALID_KEY_SIZE',
	INVALID_ASYMMETRIC_KEY_TYPE: 'INVALID_ASYMMETRIC_KEY_TYPE',
	INVALID_CURVE: 'INVALID_CURVE'
} as const

type InvalidKeyCode = (typeof invalidKeyCodes)[keyof typeof invalidKeyCodes]

export class InvalidKeyError extends Error {
	public code: InvalidKeyCode
	public constructor(message: string, code: InvalidKeyCode) {
		super(message)
		this.name = 'InvalidKeyError'
		this.code = code

		if (Error.captureStackTrace)
			Error.captureStackTrace(this, InvalidKeyError)
	}

	static invalidType(algorithm: Algorithm, expected: KeyObjectType) {
		return new InvalidKeyError(
			`Invalid key type for ${algorithm}. Expected key of type "${expected}"`,
			invalidKeyCodes.INVALID_KEY_TYPE
		)
	}

	static invalidSize(algorithm: Algorithm, bytes: number) {
		return new InvalidKeyError(
			`Invalid key size for ${algorithm}. Expected a key of size with at least ${bytes} bytes.`,
			invalidKeyCodes.INVALID_KEY_SIZE
		)
	}

	static invalidAsymmetricKeyType(algorithm: Algorithm, expected: KeyType) {
		return new InvalidKeyError(
			`Invalid asymmetric key type for ${algorithm}. Expected asymmetric key of ${expected}`,
			invalidKeyCodes.INVALID_ASYMMETRIC_KEY_TYPE
		)
	}

	static invalidCurve(algorithm: Algorithm) {
		return new InvalidKeyError(
			`Invalid curve for ${algorithm}.`,
			invalidKeyCodes.INVALID_CURVE
		)
	}
}
