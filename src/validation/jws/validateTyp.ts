import type { JWSHeaderParameters } from 'src/types/jws.js'
import { JWSError } from 'src/errors/JWSError.js'
import { isString } from '../common/isString.js'

export const validateTyp = (header: JWSHeaderParameters) => {
	if ('typ' in header && !isString(header.typ))
		throw JWSError.headerParamInvalid(
			'The "typ" header parameter must be a string'
		)
}
