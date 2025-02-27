import { Buffer } from 'node:buffer'
import { KeyObject } from 'node:crypto'
import { createFlattenedJws } from '@/serialization/flattened/createJws'
import { isObject } from '@/validation/common/typeChecks'
import { type JWSHeaderParameters } from '@/types/jws'

/**
 * Options for creating a JWS
 */
export interface CreateCompactJwsInput {
	/**
	 * The payload to sign (can be any JSON serializable value)
	 */
	payload: Buffer

	/**
	 * The protected header parameters
	 */
	protectedHeader: JWSHeaderParameters

	key: KeyObject
}

export const createCompactJws = (input: CreateCompactJwsInput): string => {
	if (!isObject(input)) throw new TypeError('Input must be an object')
	const { payload, protectedHeader, key } = input
	const {
		protected: encodedHeader,
		payload: encodedPayload,
		signature: encodedSignature
	} = createFlattenedJws({ key, payload, protectedHeader })

	return `${encodedHeader}.${encodedPayload}.${encodedSignature}`
}
