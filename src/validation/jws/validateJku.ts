import type { JWSHeaderParameters } from 'src/types/jws.js'
import { JWSError } from 'src/errors/JWSError.js'
import { isString } from '../common/isString.js'

export const validateJku = (header: JWSHeaderParameters) => {
	if (!('jku' in header)) return

	const jku = header.jku

	if (!isString(jku))
		throw JWSError.headerParamInvalid(
			'The "jku" header parameter must be a string'
		)

	try {
		const url = new URL(jku)

		if (url.protocol !== 'https:')
			throw JWSError.headerParamInvalid(
				'The "jku" header parameter must use HTTPS scheme'
			)

		if (url.hash)
			throw JWSError.headerParamInvalid(
				'The "jku" header parameter must not contain fragments'
			)

		if (url.search)
			throw JWSError.headerParamInvalid(
				'The "jku" header parameter must not contain query parameters'
			)
	} catch (error) {
		if (error instanceof JWSError) throw error
		throw JWSError.headerParamInvalid(
			'The "jku" header parameter must be a valid URL'
		)
	}
}
