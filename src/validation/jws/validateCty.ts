import type { JWSHeaderParameters } from 'src/types/jws.js'
import { JWSError } from 'src/errors/JWSError.js'
import { isString } from '../common/isString.js'

/**
 * Validates the "cty" (Content Type) Header Parameter.
 *
 * The "cty" parameter must be a string if present.
 *
 * @param header - The header object containing the optional "cty" parameter
 * @throws {JWSError} If the "cty" parameter is present but not a string
 */
export const validateCty = (header: JWSHeaderParameters) => {
	if ('cty' in header && !isString(header.cty))
		throw JWSError.headerParamInvalid(
			'The "cty" header parameter must be a string'
		)
}
