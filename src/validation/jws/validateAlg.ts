import { algorithms } from 'src/algorithms/algorithms.js'
import type { JWSHeaderParameters } from 'src/types/jws.js'

import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam.js'

export function validateAlg(
	header: Partial<JWSHeaderParameters>
): asserts header is JWSHeaderParameters {
	if (!header.alg)
		throw new InvalidJWSHeaderParam(
			'The "alg" header parameter is required',
			'alg',
			'ALG_REQUIRED'
		)

	if (!algorithms.includes(header.alg))
		throw new InvalidJWSHeaderParam(
			`Invalid algorithm: ${header.alg}`,
			'alg',
			'ALG_INVALID'
		)
}
