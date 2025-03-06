/**
 * Error codes for key errors
 */
export const KeyErrorCodes = Object.freeze({
	INVALID_KEY_TYPE: 'INVALID_KEY_TYPE',
	INVALID_KEY_SIZE: 'INVALID_KEY_SIZE',
	INVALID_ASYMMETRIC_KEY_TYPE: 'INVALID_ASYMMETRIC_KEY_TYPE',
	INVALID_CURVE: 'INVALID_CURVE'
})
export type KeyErrorCode = (typeof KeyErrorCodes)[keyof typeof KeyErrorCodes]

/**
 * Union type of all error codes
 */
export type ErrorCode = KeyErrorCode
