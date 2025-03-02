import type { JWSProtectedHeader, JWSUnprotectedHeader } from '@/types/jws'
import { isString } from '../common/isString'

const REGISTERED_HEADER_PARAMETERS = new Set([
	'alg',
	'jku',
	'jwk',
	'kid',
	'x5u',
	'x5c',
	'x5t',
	'x5t#S256',
	'typ',
	'cty',
	'crit'
])

export function validateCrit({
	protectedHeader,
	unprotectedHeader
}: {
	protectedHeader?: JWSProtectedHeader
	unprotectedHeader?: JWSUnprotectedHeader
}) {
	if (unprotectedHeader?.crit)
		throw new Error(
			'The "crit" header parameter must not be in the unprotected header'
		)

	const crit = protectedHeader?.crit

	if (!crit) return

	// Must be an array
	if (!Array.isArray(crit))
		throw new Error(
			'The "crit" header parameter must be an array of strings'
		)

	// Must not be empty
	if (crit.length === 0)
		throw new Error('The "crit" header parameter must not be empty')

	// Must contain only strings
	if (!crit.every(param => isString(param) && param.length !== 0))
		throw new Error('The "crit" header parameter must contain only strings')

	// Must not contain registered header parameter names
	const registeredParams = crit.filter(param =>
		REGISTERED_HEADER_PARAMETERS.has(param)
	)
	if (registeredParams.length > 0)
		throw new Error(
			`The "crit" header parameter must not contain registered header parameter names: ${registeredParams.join(', ')}`
		)

	// Must not contain duplicate values
	const uniqueParams = new Set(crit)
	if (uniqueParams.size !== crit.length)
		throw new Error(
			'The "crit" header parameter must not contain duplicate values'
		)

	const joseHeader = { ...protectedHeader, ...unprotectedHeader }
	const missingParams = crit.filter(param => !(param in joseHeader))
	if (missingParams.length > 0)
		throw new Error(
			`The header parameters ${missingParams.join(', ')} are not present in the JWS header, but are present in the "crit" header parameter`
		)
}
