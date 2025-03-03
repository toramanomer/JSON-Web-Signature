import { isString } from '../common/isString'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam'

export const validateTyp = (typ: undefined | string) => {
	if (!typ) return

	if (!isString(typ))
		throw new InvalidJWSHeaderParam(
			'The "typ" header parameter must be a string',
			'typ',
			'TYP_NOT_STRING'
		)
}
