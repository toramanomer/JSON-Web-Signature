import type { JWSHeaderParameters } from 'src/types/jws.js'
import { isString } from '../common/isString.js'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam.js'

export const validateCty = (header: JWSHeaderParameters) => {
	if ('cty' in header && !isString(header.cty))
		throw new InvalidJWSHeaderParam(
			'The "cty" header parameter must be a string',
			'cty',
			'CTY_NOT_STRING'
		)
}
