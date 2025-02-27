import { Buffer } from 'node:buffer'
import { KeyObject } from 'node:crypto'
import { base64UrlEncode } from '@/utils/base64UrlEncode'
import { JWSHeaderParameters } from '@/types/jws'
import { createFlattenedJws } from '@/serialization/flattened/createJws'
import { isObject } from '@/utils/isObject'

/**
 * Options for creating a JWS with general JSON serialization
 */
export interface CreateGeneralJwsInput {
	/**
	 * The payload to sign (can be any JSON serializable value)
	 */
	payload: Buffer

	/**
	 * Array of signature options
	 * Each entry will produce one signature in the output
	 */
	signatures: {
		/**
		 * The protected header parameters
		 * These parameters are integrity protected
		 */
		protectedHeader?: JWSHeaderParameters

		/**
		 * The unprotected header parameters
		 * These parameters are not integrity protected
		 */
		unprotectedHeader?: JWSHeaderParameters

		key: KeyObject
	}[]
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
