import type { JWSProtectedHeader, JWSUnprotectedHeader } from 'src/types/jws.js'
import { JWSError } from 'src/errors/JWSError.js'
import { isString } from '../common/isString.js'

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
	if (!!unprotectedHeader && 'crit' in unprotectedHeader)
		throw JWSError.headerParamInvalid(
			'The "crit" header parameter must not be in the unprotected header'
		)

	if (!!protectedHeader && !('crit' in protectedHeader)) return

	const crit = protectedHeader?.crit

	// Must be an array
	if (!Array.isArray(crit))
		throw JWSError.headerParamInvalid(
			'The "crit" header parameter must be an array of strings'
		)

	// Must not be empty
	if (crit.length === 0)
		throw JWSError.headerParamInvalid(
			'The "crit" header parameter must not be an empty array'
		)

	// Must contain only strings
	if (!crit.every(param => isString(param) && param.length !== 0))
		throw JWSError.headerParamInvalid(
			'The "crit" header parameter must contain only strings'
		)

	// Must not contain registered header parameter names
	const registeredParams = crit.filter(param =>
		REGISTERED_HEADER_PARAMETERS.has(param)
	)
	if (registeredParams.length > 0)
		throw JWSError.headerParamInvalid(
			`The "crit" header parameter must not contain registered header parameter names: ${registeredParams.join(', ')}`
		)

	// Must not contain duplicate values
	const uniqueParams = new Set(crit)
	if (uniqueParams.size !== crit.length)
		throw JWSError.headerParamInvalid(
			'The "crit" header parameter must not contain duplicate values'
		)

	const joseHeader = { ...protectedHeader, ...unprotectedHeader }
	const missingParams = crit.filter(param => !(param in joseHeader))
	if (missingParams.length > 0)
		throw JWSError.headerParamInvalid(
			`The header parameters ${missingParams.join(', ')} are not present in the JWS header, but are present in the "crit" header parameter`
		)
}
