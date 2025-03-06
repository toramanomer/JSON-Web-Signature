import type { KeyObject } from 'node:crypto'

import type { Algorithm } from 'src/algorithms/algorithms.js'
import { verifyFlattenedJws } from 'src/serialization/flattened/verifyJws.js'
import { isObject } from 'src/validation/common/isObject.js'
import { isString } from 'src/validation/common/isString.js'
import { InvalidJWSError } from 'src/validation/jws/InvalidJWSError.js'

export interface VerifyJWSOptions {
	/**
	 * The JWS to verify (in compact serialization format)
	 */
	readonly jws: string

	readonly key: KeyObject

	/**
	 * Optional list of allowed algorithms
	 * If provided, the algorithm in the JWS header must be in this list
	 */
	readonly allowedAlgorithms?: Algorithm[]
}

export function verifyCompactJws(input: VerifyJWSOptions) {
	if (!isObject(input)) throw new TypeError('The "input" must be an object')

	const { jws, key, allowedAlgorithms } = input

	if (!isString(jws))
		throw InvalidJWSError.invalidFormat(
			'JWS Compact Serialization must be a string'
		)

	const {
		0: encodedHeader,
		1: encodedPayload,
		2: encodedSignature,
		length
	} = jws.split('.')

	if (length !== 3)
		throw InvalidJWSError.invalidFormat(
			'JWS Compact Serialization must have 3 components'
		)

	verifyFlattenedJws({
		jws: {
			payload: encodedPayload,
			signature: encodedSignature,
			protected: encodedHeader
		},
		key,
		allowedAlgorithms
	})

	return jws
}
