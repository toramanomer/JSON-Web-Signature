import type { JWSHeaderParameters } from '@/types/jws.js'
import { isString } from '../common/isString.js'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam.js'

export const validateTyp = (header: JWSHeaderParameters) => {
	if ('typ' in header && !isString(header.typ))
		throw new InvalidJWSHeaderParam(
			'The "typ" header parameter must be a string',
			'typ',
			'TYP_NOT_STRING'
		)
}
