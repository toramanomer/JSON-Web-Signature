import { JWSHeaderParameters } from '@/types/jws'
import { algorithms } from '@/algorithms/algorithms'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam'

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
