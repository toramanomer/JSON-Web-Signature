export class InvalidJWSHeaderParam extends Error {
	headerParameter: string
	code?: string

	/**
	 * @param message The error message
	 * @param headerParameter The name of the header parameter that failed validation
	 * @param code Optional. Error code for categorizing errors
	 */
	constructor(message: string, headerParameter: string, code?: string) {
		super(message)
		this.name = 'InvalidJWSHeaderParam'
		this.headerParameter = headerParameter
		this.code = code

		if (Error.captureStackTrace) {
			Error.captureStackTrace(this, InvalidJWSHeaderParam)
		}
	}
}
