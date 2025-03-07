import { BaseError } from './BaseError.js'
import { JWSErrorCodes, type JWSErrorCode } from './codes.js'

export class JWSError extends BaseError {
	readonly code: JWSErrorCode

	constructor(message: string, code: JWSErrorCode) {
		super(message)
		this.code = code
	}

	static invalidFormat(message: string) {
		return new JWSError(message, JWSErrorCodes.INVALID_JWS_FORMAT)
	}

	static invalidProtectedHeader(message: string) {
		return new JWSError(message, JWSErrorCodes.INVALID_PROTECTED_HEADER)
	}

	static invalidUnprotectedHeader(message: string) {
		return new JWSError(message, JWSErrorCodes.INVALID_UNPROTECTED_HEADER)
	}

	static invalidPayload(message: string) {
		return new JWSError(message, JWSErrorCodes.INVALID_PAYLOAD)
	}

	static invalidSignature(message: string = 'Invalid signature') {
		return new JWSError(message, JWSErrorCodes.INVALID_SIGNATURE)
	}

	static invalidSignatureEncoding(message: string) {
		return new JWSError(message, JWSErrorCodes.INVALID_SIGNATURE_ENCODING)
	}

	static headerParametersNotDisjoint() {
		return new JWSError(
			'Header Parameter names must be disjoint between protected and unprotected headers',
			JWSErrorCodes.HEADER_PARAMETERS_NOT_DISJOINT
		)
	}

	static missingHeaders() {
		return new JWSError(
			'Either protected header or unprotected header must be present',
			JWSErrorCodes.MISSING_HEADERS
		)
	}

	static headerParamInvalid(message: string) {
		return new JWSError(message, JWSErrorCodes.HEADER_PARAM_INVALID)
	}
}
