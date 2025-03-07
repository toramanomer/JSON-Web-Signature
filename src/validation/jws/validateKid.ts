import type { JWSHeaderParameters } from 'src/types/jws.js'
import { isString } from '../common/isString.js'
import { JWSError } from '../../errors/JWSError.js'

export const validateKid = (header: JWSHeaderParameters) => {
	if (!('kid' in header)) return

	const kid = header.kid

	if (!isString(kid))
		throw JWSError.headerParamInvalid(
			'The "kid" header parameter must be a string'
		)

	if (kid.trim().length === 0)
		throw JWSError.headerParamInvalid(
			'The "kid" header parameter must not be empty'
		)
}
