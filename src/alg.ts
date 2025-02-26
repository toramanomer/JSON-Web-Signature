/**
 * Supported algorithms for JWS
 */
export const AlgorithmParameterValues = {
	// HMAC with SHA-2 Functions
	HS256: 'HS256',
	HS384: 'HS384',
	HS512: 'HS512',

	// Digital Signature with RSASSA-PKCS1-v1_5
	RS256: 'RS256',
	RS384: 'RS384',
	RS512: 'RS512',
	ES256: 'ES256',
	ES384: 'ES384',
	ES512: 'ES512',
	PS256: 'PS256',
	PS384: 'PS384',
	PS512: 'PS512'
}

export type AlgorithmParameterValue = keyof typeof AlgorithmParameterValues
