import type { KeyObject } from 'node:crypto'

import type { Algorithm } from 'src/algorithms/algorithms.js'
import { verifyFlattenedJws } from 'src/serialization/flattened/verifyJws.js'
import { isObject } from 'src/validation/common/isObject.js'

export interface VerifyJWSOptions {
	/**
	 * The JWS to verify (in compact serialization format)
	 */
	jws: string

	key: KeyObject

	allowedAlgorithms?: Algorithm[]
}

export function verifyCompactJws(input: VerifyJWSOptions) {
	if (!isObject(input))
		throw new TypeError('The "input" argument must be of type object')

	const { jws, key, allowedAlgorithms } = input

	const {
		0: encodedHeader,
		1: encodedPayload,
		2: encodedSignature,
		length
	} = jws.split('.')

	if (length !== 3) throw new Error('JWS is missing a component')

	return verifyFlattenedJws({
		jws: {
			payload: encodedPayload,
			signature: encodedSignature,
			protected: encodedHeader
		},
		key,
		allowedAlgorithms
	})
}
