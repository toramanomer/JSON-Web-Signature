import { base64UrlEncode } from '@/encoding/base64url'
import {
	createFlattenedJws,
	type CreateFlattenedJwsInput
} from '@/serialization/flattened/createJws'
import { isObject } from '@/validation/common/typeChecks'

/**
 * Options for creating a JWS with general JSON serialization
 */
export interface CreateGeneralJwsInput
	extends Pick<CreateFlattenedJwsInput, 'payload'> {
	/**
	 * Array of signature options
	 * Each entry will produce one signature in the output
	 */
	signatures: Omit<CreateFlattenedJwsInput, 'payload'>[]
}

export const createGeneralJws = (input: CreateGeneralJwsInput) => {
	if (!isObject(input)) throw new TypeError('Argument must be an object')
	if (!input.signatures?.length)
		throw new Error('At least one signature must be provided')

	const encodedPayload = base64UrlEncode(input.payload)

	const signatures = input.signatures.map(
		({ key, unprotectedHeader, protectedHeader }) => {
			return createFlattenedJws({
				key,
				payload: input.payload,
				protectedHeader,
				unprotectedHeader
			})
		}
	)
	return { payload: encodedPayload, signatures }
}
