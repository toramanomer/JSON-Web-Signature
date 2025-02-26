import { KeyObject } from 'node:crypto'
import { AlgorithmParameterValue } from '@/utils/alg'
import { verifyFlattenedJws } from '@/flattened/verifyJws'
import { isObject } from '@/utils/isObject'

export interface VerifyJWSOptions {
	/**
	 * The JWS to verify (in compact serialization format)
	 */
	jws: string

	key: KeyObject

	allowedAlgorithms?: AlgorithmParameterValue[]
}

export function verifyCompactJws(input: VerifyJWSOptions) {
	if (!isObject(input)) throw new TypeError('Expected object')

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
