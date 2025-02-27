import { isString } from '@/validation/common/typeChecks'

export const validateTyp = (typ: undefined | string) => {
	if (!typ) return

	if (!isString(typ))
		throw new Error('The "typ" header parameter must be a string')
}
