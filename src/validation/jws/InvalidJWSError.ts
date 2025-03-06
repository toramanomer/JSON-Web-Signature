/**
 * Error codes for JWS validation failures
 */
export type InvalidJWSErrorCode =
	| 'INVALID_FORMAT'
	| 'INVALID_PROTECTED_HEADER'
	| 'INVALID_UNPROTECTED_HEADER'
	| 'INVALID_PAYLOAD'
	| 'INVALID_SIGNATURE'
	| 'INVALID_SIGNATURE_ENCODING'
	| 'HEADER_PARAMETERS_NOT_DISJOINT'
	| 'MISSING_HEADERS'

/**
 * Error thrown when JWS validation fails
 */
export class InvalidJWSError extends Error {
	readonly code: InvalidJWSErrorCode

	constructor(message: string, code: InvalidJWSErrorCode) {
		super(message)
		this.name = 'InvalidJWSError'
		this.code = code
	}

	static invalidFormat(message: string) {
		return new InvalidJWSError(message, 'INVALID_FORMAT')
	}

	static invalidProtectedHeader(message: string) {
		return new InvalidJWSError(message, 'INVALID_PROTECTED_HEADER')
	}

	static invalidUnprotectedHeader(message: string) {
		return new InvalidJWSError(message, 'INVALID_UNPROTECTED_HEADER')
	}

	static invalidPayload(message: string) {
		return new InvalidJWSError(message, 'INVALID_PAYLOAD')
	}

	static invalidSignature(message: string = 'Invalid signature') {
		return new InvalidJWSError(message, 'INVALID_SIGNATURE')
	}

	static invalidSignatureEncoding(message: string) {
		return new InvalidJWSError(message, 'INVALID_SIGNATURE_ENCODING')
	}

	static headerParametersNotDisjoint() {
		return new InvalidJWSError(
			'Header Parameter names must be disjoint between protected and unprotected headers',
			'HEADER_PARAMETERS_NOT_DISJOINT'
		)
	}

	static missingHeaders() {
		return new InvalidJWSError(
			'Either protected header or unprotected header must be present',
			'MISSING_HEADERS'
		)
	}
}
