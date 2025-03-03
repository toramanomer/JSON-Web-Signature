import { JWSHeaderParameters } from '@/types/jws'
import { isString } from '../common/isString'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam'

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
