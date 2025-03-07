import type { JWSHeaderParameters } from 'src/types/jws.js'
import { JWSError } from 'src/errors/JWSError.js'
import { isString } from '../common/isString.js'

export const validateCty = (header: JWSHeaderParameters) => {
	if ('cty' in header && !isString(header.cty))
		throw JWSError.headerParamInvalid(
			'The "cty" header parameter must be a string'
		)
}
