import type { KeyObjectType, KeyType } from 'node:crypto'
import type { Algorithm } from '../algorithms/algorithms.js'
import { BaseError } from './BaseError.js'
import { KeyErrorCodes, type KeyErrorCode } from './codes.js'

export class KeyError extends BaseError {
	public readonly code: KeyErrorCode

	constructor(message: string, code: KeyErrorCode) {
		super(message)
		this.code = code
	}

	static invalidType(algorithm: Algorithm, expected: KeyObjectType) {
		return new KeyError(
			`Invalid key type for ${algorithm}. Expected key of type "${expected}"`,
			KeyErrorCodes.INVALID_KEY_TYPE
		)
	}

	static invalidSize(algorithm: Algorithm, bytes: number) {
		return new KeyError(
			`Invalid key size for ${algorithm}. Expected a key of size with at least ${bytes} bytes.`,
			KeyErrorCodes.INVALID_KEY_SIZE
		)
	}

	static invalidAsymmetricKeyType(algorithm: Algorithm, expected: KeyType) {
		return new KeyError(
			`Invalid asymmetric key type for ${algorithm}. Expected asymmetric key of ${expected}`,
			KeyErrorCodes.INVALID_ASYMMETRIC_KEY_TYPE
		)
	}

	static invalidCurve(algorithm: Algorithm) {
		return new KeyError(
			`Invalid curve for ${algorithm}.`,
			KeyErrorCodes.INVALID_CURVE
		)
	}
}
