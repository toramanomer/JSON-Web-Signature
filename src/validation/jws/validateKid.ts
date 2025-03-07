import type { JWSHeaderParameters } from 'src/types/jws.js'
import { JWSError } from 'src/errors/JWSError.js'
import { isString } from '../common/isString.js'

/**
 * Validates the "kid" (Key ID) Header Parameter.
 *
 * The "kid" parameter must:
 * - Be a string
 * - Not be empty or only whitespace
 *
 * @param header - The header object containing the optional "kid" parameter
 * @throws {JWSError} If the "kid" parameter is present but invalid
 */
export const validateKid = (header: JWSHeaderParameters) => {
	if (!('kid' in header)) return

	const kid = header.kid

	if (!isString(kid))
		throw JWSError.headerParamInvalid(
			'The "kid" header parameter must be a string'
		)

	if (kid.trim().length === 0)
		throw JWSError.headerParamInvalid(
			'The "kid" header parameter must not be empty'
		)
}
