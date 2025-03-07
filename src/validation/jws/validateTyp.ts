import type { JWSHeaderParameters } from 'src/types/jws.js'
import { isString } from '../common/isString.js'
import { JWSError } from '../../errors/JWSError.js'

export const validateTyp = (header: JWSHeaderParameters) => {
	if ('typ' in header && !isString(header.typ))
		throw JWSError.headerParamInvalid(
			'The "typ" header parameter must be a string'
		)
}
