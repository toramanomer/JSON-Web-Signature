import { Buffer } from 'node:buffer'
import { KeyObject } from 'node:crypto'
import { type Algorithm } from '@/algorithms/algorithms'
import { createFlattenedJws } from '@/serialization/flattened/createJws'
import { isObject } from '@/utils/isObject'

export interface JWSHeaderParameters {
	/**
	 * **"alg" (Algorithm) Header Parameter**
	 *
	 * The "alg" (algorithm) Header Parameter identifies the cryptographic
	 * algorithm used to secure the JWS.
	 */
	'alg': Algorithm

	/**
	 * **"jku" (JWK Set URL) Header Parameter**
	 *
	 * The "jku" (JWK Set URL) Header Parameter is a URI that refers to a resource
	 * for a set of JSON-encoded public keys, one of which corresponds to the key
	 * used to digitally sign the JWS.
	 */
	'jku'?: string

	/**
	 * **"jwk" (JSON Web Key) Header Parameter**
	 *
	 * The "jwk" (JSON Web Key) Header Parameter is the public key that
	 * corresponds to the key used to digitally sign the JWS.
	 */
	'jwk'?: Record<string, any>

	/**
	 * **"kid" (Key ID) Header Parameter**
	 *
	 * The "kid" (key ID) Header Parameter is a hint indicating which key
	 * was used to secure the JWS.
	 */
	'kid'?: string

	/**
	 * **"x5u" (X.509 URL) Header Parameter**
	 *
	 * The "x5u" (X.509 URL) Header Parameter is a URI that refers to a resource
	 * for the X.509 public key certificate or certificate chain corresponding
	 * to the key used to digitally sign the JWS.
	 */
	'x5u'?: string

	/**
	 * **"x5c" (X.509 Certificate Chain) Header Parameter**
	 *
	 * The "x5c" (X.509 Certificate Chain) Header Parameter contains the X.509
	 * public key certificate or certificate chain corresponding to the key used
	 * to digitally sign the JWS.
	 */
	'x5c'?: string[]

	/**
	 * **"x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter**
	 *
	 * The "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter is a
	 * base64url-encoded SHA-1 thumbprint of the DER encoding of the X.509
	 * certificate corresponding to the key used to digitally sign the JWS.
	 */
	'x5t'?: string

	/**
	 * **"x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter**
	 *
	 * The "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter is a
	 * base64url-encoded SHA-256 thumbprint of the DER encoding of the X.509
	 * certificate corresponding to the key used to digitally sign the JWS.
	 */
	'x5t#S256'?: string

	/**
	 * **"typ" (Type) Header Parameter**
	 *
	 * The "typ" (type) Header Parameter is used by JWS applications to declare
	 * the media type of this complete JWS.
	 */
	'typ'?: string

	/**
	 * **"cty" (Content Type) Header Parameter**
	 *
	 * The "cty" (content type) Header Parameter is used by JWS applications to
	 * declare the media type of the secured content (the payload).
	 */
	'cty'?: string

	/**
	 * **"crit" (Critical) Header Parameter**
	 *
	 * The "crit" (critical) Header Parameter indicates that extensions to
	 * this specification and/or JWA are being used that MUST be understood
	 * and processed.
	 */
	'crit'?: string[]

	/**
	 * Allow for additional parameters
	 */
	[key: string]: any
}

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
