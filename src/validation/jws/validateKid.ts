import { isString } from '@/validation/common/typeChecks'

export const validateKid = (kid: undefined | string) => {
	if (!kid) return

	if (!isString(kid))
		throw new Error('The "kid" header parameter must be a string')

	if (kid.trim().length === 0)
		throw new Error('The "kid" header parameter must not be empty')
}
