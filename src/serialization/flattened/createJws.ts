import type { KeyObject } from 'node:crypto'
import { Buffer } from 'node:buffer'
import { isKeyObject } from 'node:util/types'

import type { JWSProtectedHeader, JWSUnprotectedHeader } from 'src/types/jws.js'
import { base64UrlEncode } from 'src/encoding/base64url.js'
import { createSignature } from 'src/crypto/sign.js'

import { isObject } from 'src/validation/common/isObject.js'
import { isDisjoint } from 'src/validation/common/isDisjoint.js'
import { isJsonObject } from 'src/validation/common/isJsonObject.js'

import { validateAlg } from 'src/validation/jws/validateAlg.js'
import { validateJku } from 'src/validation/jws/validateJku.js'
import { validateJwk } from 'src/validation/jws/validateJwk.js'
import { validateKid } from 'src/validation/jws/validateKid.js'
import { validateTyp } from 'src/validation/jws/validateTyp.js'
import { validateCty } from 'src/validation/jws/validateCty.js'
import { validateCrit } from 'src/validation/jws/validateCrit.js'

/**
 * Options for creating a JWS with flattened JSON serialization
 */
export interface CreateFlattenedJwsInput {
	/**
	 * **JWS Payload**
	 *
	 * The sequence of octets to be secured -- a.k.a. the message.
	 * The payload can contain an arbitrary sequence of octets.
	 */
	payload: Buffer

	/**
	 * **JWS Protected Header**
	 *
	 * JSON object that contains the Header Parameters that are integrity
	 * protected by the JWS Signature digital signature or MAC operation.
	 *
	 * - The header is integrity-protected, meaning it is included in the signing process.
	 * - The names of the header parameters in the protected header **must** be disjoint from the unprotected header.
	 */
	protectedHeader?: JWSProtectedHeader

	/**
	 * **JWS Unprotected Header**
	 *
	 * JSON object that contains the Header Parameters that are **not**
	 * integrity protected.
	 *
	 * - The header is not integrity-protected, meaning it is not included in the signing process.
	 * - The names of the header parameters in the unprotected header **must** be disjoint from the protected header.
	 */
	unprotectedHeader?: JWSUnprotectedHeader

	/**
	 * The key used for signing.
	 *
	 * The key type and requirements depend on the **"alg"** header parameter value.
	 * Different algorithms require different key types and sizes:
	 *
	 * ### HMAC
	 * - `"HS256"`: Secret key with at least 256 bits
	 * - `"HS384"`: Secret key with at least 384 bits
	 * - `"HS512"`: Secret key with at least 512 bits
	 *
	 * ### RSASSA-PKCS1-v1_5
	 * - `"RS256"`: Public RSA key with at least 2048-bit modulus
	 * - `"RS384"`: Public RSA key with at least 2048-bit modulus
	 * - `"RS512"`: Public RSA key with at least 2048-bit modulus
	 *
	 * ### ECDSA
	 * - `"ES256"`: Public EC key with a P-256 curve
	 * - `"ES384"`: Public EC key with a P-384 curve
	 * - `"ES512"`: Public EC key with a P-521 curve
	 *
	 * ### RSASSA-PSS
	 * - `"PS256"`: Public RSASSA-PSS key with at least 2048-bit modulus
	 * - `"PS384"`: Public RSASSA-PSS key with at least 2048-bit modulus
	 * - `"PS512"`: Public RSASSA-PSS key with at least 2048-bit modulus
	 *
	 * **Note**: The exact requirements for the key depend on the algorithm specified in the "alg" header.
	 */
	key: KeyObject
}

export const createFlattenedJws = (input: CreateFlattenedJwsInput) => {
	if (!isObject(input))
		throw new TypeError('The "input" argument must be of type object')

	const { key, payload, protectedHeader, unprotectedHeader } = input

	if (!isKeyObject(key))
		throw new TypeError('The provided key must be an instance of KeyObject')

	// Validate payload
	if (!Buffer.isBuffer(payload))
		throw new TypeError('payload must be a buffer')

	// Validate protectedHeader if present
	if (
		Object.hasOwn(input, 'protectedHeader') &&
		!isJsonObject(protectedHeader)
	)
		throw new TypeError('protectedHeader must be an object if provided')
	// Validate protectedHeader if present
	if (
		Object.hasOwn(input, 'unprotectedHeader') &&
		!isJsonObject(unprotectedHeader)
	)
		throw new TypeError('unprotectedHeader must be an object if provided')

	// Ensure at least one of protectedHeader or unprotectedHeader is provided
	if (!protectedHeader && !unprotectedHeader)
		throw new Error(
			'Either protectedHeader or unprotectedHeader must be provided'
		)

	// Ensure header parameter names are disjoint
	if (!isDisjoint(protectedHeader, unprotectedHeader))
		throw new Error(
			`Header Parameter names must be disjoint between protected and unprotected headers.`
		)

	const joseHeader = { ...protectedHeader, ...unprotectedHeader }

	validateAlg(joseHeader)
	validateJku(joseHeader)
	validateJwk(joseHeader)
	validateKid(joseHeader)
	validateTyp(joseHeader)
	validateCty(joseHeader)
	validateCrit({ protectedHeader, unprotectedHeader })

	const encodedPayload = base64UrlEncode(payload)
	const encodedProtectedHeader =
		protectedHeader ? base64UrlEncode(JSON.stringify(protectedHeader)) : ''
	const signingInput = `${encodedProtectedHeader}.${encodedPayload}`

	const signature = createSignature(signingInput, joseHeader.alg, key)
	const encodedSignature = base64UrlEncode(signature)

	return {
		payload: encodedPayload,
		...(!!protectedHeader && { protected: encodedProtectedHeader }),
		...(!!unprotectedHeader && { header: unprotectedHeader }),
		signature: encodedSignature
	}
}
