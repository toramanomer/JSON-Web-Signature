import type { JWSHeaderParameters } from 'src/types/jws.js'
import { isString } from '../common/isString.js'
import { JWSError } from '../../errors/JWSError.js'

export const validateCty = (header: JWSHeaderParameters) => {
	if ('cty' in header && !isString(header.cty))
		throw JWSError.headerParamInvalid(
			'The "cty" header parameter must be a string'
		)
}
