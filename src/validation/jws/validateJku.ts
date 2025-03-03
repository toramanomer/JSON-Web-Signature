import { JWSHeaderParameters } from '@/types/jws'
import { isString } from '../common/isString'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam'

export const validateJku = (header: JWSHeaderParameters) => {
	if (!('jku' in header)) return

	const jku = header.jku

	if (!isString(jku))
		throw new InvalidJWSHeaderParam(
			'The "jku" header parameter must be a string',
			'jku',
			'JKU_NOT_STRING'
		)

	try {
		const url = new URL(jku)

		if (url.protocol !== 'https:')
			throw new InvalidJWSHeaderParam(
				'The "jku" header parameter must use HTTPS scheme',
				'jku',
				'JKU_NOT_HTTPS'
			)

		if (url.hash)
			throw new InvalidJWSHeaderParam(
				'The "jku" header parameter must not contain fragments',
				'jku',
				'JKU_CONTAINS_FRAGMENTS'
			)

		if (url.search)
			throw new InvalidJWSHeaderParam(
				'The "jku" header parameter must not contain query parameters',
				'jku',
				'JKU_CONTAINS_QUERY_PARAMS'
			)
	} catch (error) {
		if (error instanceof InvalidJWSHeaderParam) throw error
		throw new InvalidJWSHeaderParam(
			'The "jku" header parameter must be a valid URL',
			'jku',
			'JKU_INVALID_URL'
		)
	}
}
