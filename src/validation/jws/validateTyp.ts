import type { JWSHeaderParameters } from 'src/types/jws.js'
import { JWSError } from 'src/errors/JWSError.js'
import { isString } from '../common/isString.js'

/**
 * Validates the "typ" (Type) Header Parameter.
 *
 * The "typ" parameter must be a string if present.
 *
 * @param header - The header object containing the optional "typ" parameter
 * @throws {JWSError} If the "typ" parameter is present but not a string
 */
export const validateTyp = (header: JWSHeaderParameters) => {
	if ('typ' in header && !isString(header.typ))
		throw JWSError.headerParamInvalid(
			'The "typ" header parameter must be a string'
		)
}
