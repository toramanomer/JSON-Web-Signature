import { isString } from '@/validation/common/typeChecks'

export const validateJku = (jku: undefined | string) => {
	if (!jku) return

	if (!isString(jku))
		throw new Error('The "jku" header parameter must be a string')

	const url = new URL(jku)

	if (url.protocol !== 'https:')
		throw new Error('The "jku" header parameter must use HTTPS scheme')

	if (url.hash)
		throw new Error('The "jku" header parameter must not contain fragments')
}
