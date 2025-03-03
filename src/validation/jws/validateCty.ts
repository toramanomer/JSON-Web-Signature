import { isString } from '../common/isString'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam'

export const validateCty = (cty: undefined | string) => {
	if (!cty) return

	if (!isString(cty))
		throw new InvalidJWSHeaderParam(
			'The "cty" header parameter must be a string',
			'cty',
			'CTY_NOT_STRING'
		)
}
