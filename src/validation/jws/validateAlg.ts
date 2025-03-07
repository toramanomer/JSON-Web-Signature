import { algorithms, type Algorithm } from 'src/algorithms/algorithms.js'
import type { JWSHeaderParameters } from 'src/types/jws.js'
import { JWSError } from 'src/errors/JWSError.js'

/**
 * Validates the "alg" (Algorithm) Header Parameter.
 *
 * The "alg" parameter must be a string that is one of the supported algorithms.
 *
 * @param header - The header object containing the "alg" parameter to validate
 * @param allowedAlgorithms - Optional. List of allowed algorithms. Defaults to all supported algorithms {@link algorithms}
 * @throws {JWSError} If the "alg" parameter is missing or not an allowed algorithm
 */
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
