import { algorithms, type Algorithm } from 'src/algorithms/algorithms.js'
import type { JWSHeaderParameters } from 'src/types/jws.js'
import { JWSError } from 'src/errors/JWSError.js'

export function validateAlg(
	header: Partial<JWSHeaderParameters>,
	allowedAlgorithms: ReadonlyArray<Algorithm> = algorithms
): asserts header is JWSHeaderParameters {
	if (!header.alg)
		throw JWSError.headerParamInvalid(
			'The "alg" header parameter is required'
		)

	if (!allowedAlgorithms.includes(header.alg))
		throw JWSError.headerParamInvalid(`Invalid algorithm: ${header.alg}`)
}
