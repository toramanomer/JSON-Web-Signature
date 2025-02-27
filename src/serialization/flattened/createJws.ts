import { Buffer } from 'node:buffer'
import { KeyObject } from 'node:crypto'

import { base64UrlEncode } from '@/encoding/base64url'
import { JWSHeaderParameters } from '@/types/jws'
import { isObject, isDisjoint } from '@/validation/common/typeChecks'
import { createSignature } from '@/crypto/sign'
import { validateJwk } from '@/validation/jws/validateJwk'
import { validateKid } from '@/validation/jws/validateKid'
import { validateJku } from '@/validation/jws/validateJku'

/**
 * Options for creating a JWS with flattened JSON serialization
 */
export interface CreateFlattenedJwsInput {
	/**
	 * The payload to sign (can be any JSON serializable value)
	 */
	payload: Buffer

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

	/**
	 * The key used for signing
	 */
	key: KeyObject
}

export const createFlattenedJws = (input: CreateFlattenedJwsInput) => {
	if (!isObject(input)) throw new TypeError('Argument must be an object')

	const { key, payload, protectedHeader, unprotectedHeader } = input

	// Validate payload
	if (!Buffer.isBuffer(payload))
		throw new TypeError('payload must be a buffer')

	// Validate protectedHeader if present
	if (!!protectedHeader && !isObject(protectedHeader))
		throw new TypeError('protectedHeader must be an object if provided')
	// Validate protectedHeader if present
	if (!!unprotectedHeader && !isObject(unprotectedHeader))
		throw new TypeError('unprotectedHeader must be an object if provided')

	// Ensure at least one of protectedHeader or unprotectedHeader is provided
	if (!protectedHeader && !unprotectedHeader) {
		throw new Error(
			'Either protectedHeader or unprotectedHeader must be provided'
		)
	}

	// Ensure header parameter names are disjoint
	if (!isDisjoint(protectedHeader, unprotectedHeader))
		throw new Error(
			`Header Parameter names must be disjoint between protected and unprotected headers.`
		)

	const algorithm = protectedHeader?.alg || unprotectedHeader?.alg
	if (!algorithm) throw new Error('algorithm is missing')

	// Validate header parameters in both protected and unprotected headers
	if (protectedHeader) {
		validateJwk(protectedHeader)
		validateKid(protectedHeader)
		validateJku(protectedHeader)
	}
	if (unprotectedHeader) {
		validateJwk(unprotectedHeader)
		validateKid(unprotectedHeader)
		validateJku(unprotectedHeader)
	}

	const encodedPayload = base64UrlEncode(payload)
	const encodedProtectedHeader =
		protectedHeader ? base64UrlEncode(JSON.stringify(protectedHeader)) : ''
	const signingInput = `${encodedProtectedHeader}.${encodedPayload}`

	const signature = createSignature(signingInput, algorithm, key)
	const encodedSignature = base64UrlEncode(signature)

	return {
		payload: encodedPayload,
		...(!!protectedHeader && { protected: encodedProtectedHeader }),
		...(!!unprotectedHeader && { header: unprotectedHeader }),
		signature: encodedSignature
	}
}
