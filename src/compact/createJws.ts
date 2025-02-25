import { Buffer } from 'node:buffer'
import { AlgorithmParameterValue } from '@/alg'
import { base64UrlEncode } from '@/utils/base64UrlEncode'
import { createSignature } from '@/utils/createSignature'

/**
 * JWS Header Parameters as defined in RFC 7515
 * https://tools.ietf.org/html/rfc7515#section-4.1
 */
export interface JWSHeaderParameters {
	/**
	 * **"alg" (Algorithm) Header Parameter**
	 *
	 * The "alg" (algorithm) Header Parameter identifies the cryptographic
	 * algorithm used to secure the JWS.
	 */
	'alg': AlgorithmParameterValue

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
export interface CreateJWSOptions {
	/**
	 * The payload to sign (can be any JSON serializable value)
	 */
	payload: any

	/**
	 * The protected header parameters
	 */
	protectedHeader: JWSHeaderParameters

	/**
	 * The key used for signing
	 * - For HMAC algorithms: a string or Buffer containing the secret
	 * - For RSA and ECDSA algorithms: a private key in PEM format
	 */
	key: string | Buffer
}

/**
 * Creates a JWS according to RFC 7515
 * Returns the JWS in compact serialization format
 */
export function createJws({
	payload,
	protectedHeader,
	key
}: CreateJWSOptions): string {
	// Step 1: Create the content to be used as the JWS Payload
	const payloadStr =
		typeof payload === 'string' ? payload : JSON.stringify(payload)

	// Step 2: Compute the encoded payload value
	const encodedPayload = base64UrlEncode(payloadStr)

	// Step 3 & 4: Create the header and compute the encoded header value
	const encodedHeader = base64UrlEncode(JSON.stringify(protectedHeader))

	// Step 5: Compute the JWS Signature
	const signingInput = `${encodedHeader}.${encodedPayload}`
	const signature = createSignature(signingInput, protectedHeader.alg, key)

	// Step 6: Compute the encoded signature value
	const encodedSignature = base64UrlEncode(signature)

	// Step 8: Create the JWS Compact Serialization
	return `${encodedHeader}.${encodedPayload}.${encodedSignature}`
}
