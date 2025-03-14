import type { JWSProtectedHeader } from 'src/types/jws.js'
import {
	createFlattenedJws,
	type CreateFlattenedJwsInput
} from 'src/serialization/flattened/createJws.js'
import { isObject } from 'src/validation/common/isObject.js'

/**
 * Options for creating a JWS with compact serialization
 */
export interface CreateCompactJwsInput
	extends Pick<CreateFlattenedJwsInput, 'payload' | 'key'> {
	/**
	 * **JWS Protected Header**
	 *
	 * JSON object that contains the Header Parameters that are integrity
	 * protected by the JWS Signature digital signature or MAC operation.
	 *
	 * - The header is integrity-protected, meaning it is included in the signing process.
	 */
	protectedHeader: JWSProtectedHeader
}

export const createCompactJws = (input: CreateCompactJwsInput): string => {
	if (!isObject(input))
		throw new TypeError('The "input" argument must be of type object')

	const { payload, protectedHeader, key } = input
	const {
		protected: encodedHeader,
		payload: encodedPayload,
		signature: encodedSignature
	} = createFlattenedJws({ key, payload, protectedHeader })

	return `${encodedHeader}.${encodedPayload}.${encodedSignature}`
}
