import type { JWSProtectedHeader, JWSUnprotectedHeader } from '@/types/jws'
import { isString } from '../common/isString'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam'

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
		throw new InvalidJWSHeaderParam(
			'The "crit" header parameter must not be in the unprotected header',
			'crit',
			'CRIT_IN_UNPROTECTED'
		)

	const crit = protectedHeader?.crit

	if (!crit) return

	// Must be an array
	if (!Array.isArray(crit))
		throw new InvalidJWSHeaderParam(
			'The "crit" header parameter must be an array of strings',
			'crit',
			'CRIT_NOT_ARRAY'
		)

	// Must not be empty
	if (crit.length === 0)
		throw new InvalidJWSHeaderParam(
			'The "crit" header parameter must not be empty',
			'crit',
			'CRIT_EMPTY'
		)

	// Must contain only strings
	if (!crit.every(param => isString(param) && param.length !== 0))
		throw new InvalidJWSHeaderParam(
			'The "crit" header parameter must contain only strings',
			'crit',
			'CRIT_INVALID_ENTRIES'
		)

	// Must not contain registered header parameter names
	const registeredParams = crit.filter(param =>
		REGISTERED_HEADER_PARAMETERS.has(param)
	)
	if (registeredParams.length > 0)
		throw new InvalidJWSHeaderParam(
			`The "crit" header parameter must not contain registered header parameter names: ${registeredParams.join(', ')}`,
			'crit',
			'CRIT_REGISTERED_PARAMS'
		)

	// Must not contain duplicate values
	const uniqueParams = new Set(crit)
	if (uniqueParams.size !== crit.length)
		throw new InvalidJWSHeaderParam(
			'The "crit" header parameter must not contain duplicate values',
			'crit',
			'CRIT_DUPLICATE_VALUES'
		)

	const joseHeader = { ...protectedHeader, ...unprotectedHeader }
	const missingParams = crit.filter(param => !(param in joseHeader))
	if (missingParams.length > 0)
		throw new InvalidJWSHeaderParam(
			`The header parameters ${missingParams.join(', ')} are not present in the JWS header, but are present in the "crit" header parameter`,
			'crit',
			'CRIT_MISSING_PARAMS'
		)
}
