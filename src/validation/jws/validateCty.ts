import { isString } from '../common/isString'

export const validateCty = (cty: undefined | string) => {
	if (!cty) return

	if (!isString(cty))
		throw new Error('The "cty" header parameter must be a string')
}
