/**
 * Base error class for all errors in the library.
 */
export class BaseError extends Error {
	/**
	 * @param message Human-readable description of the error
	 */
	constructor(message: string) {
		super(message)
		this.name = this.constructor.name

		if (Error.captureStackTrace)
			Error.captureStackTrace(this, this.constructor)
	}
}
