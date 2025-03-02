import { KeyObject } from 'node:crypto'
import { type Algorithm } from '@/algorithms/algorithms'
import { verifyFlattenedJws } from '@/serialization/flattened/verifyJws'
import { isJsonObject } from '@/validation/common/isJsonObject'

export interface VerifyJWSOptions {
	/**
	 * The JWS to verify (in compact serialization format)
	 */
	jws: string

	key: KeyObject

	allowedAlgorithms?: Algorithm[]
}

export function verifyCompactJws(input: VerifyJWSOptions) {
	if (!isJsonObject(input)) throw new TypeError('Expected object')

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
