import type { JWSHeaderParameters } from '@/types/jws'
import { isString } from '../common/isString'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam'

export const validateCty = (header: JWSHeaderParameters) => {
	if ('cty' in header && !isString(header.cty))
		throw new InvalidJWSHeaderParam(
			'The "cty" header parameter must be a string',
			'cty',
			'CTY_NOT_STRING'
		)
}
