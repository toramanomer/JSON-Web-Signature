import type { JWSHeaderParameters } from 'src/types/jws.js'
import { isString } from '../common/isString.js'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam.js'

export const validateKid = (header: JWSHeaderParameters) => {
	if (!('kid' in header)) return

	const kid = header.kid

	if (!isString(kid))
		throw new InvalidJWSHeaderParam(
			'The "kid" header parameter must be a string',
			'kid',
			'KID_NOT_STRING'
		)

	if (kid.trim().length === 0)
		throw new InvalidJWSHeaderParam(
			'The "kid" header parameter must not be empty',
			'kid',
			'KID_EMPTY'
		)
}
