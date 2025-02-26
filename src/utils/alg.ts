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

	// Digital Signature with ECDSA
	ES256: 'ES256',
	ES384: 'ES384',
	ES512: 'ES512',

	// Digital Signature with RSASSA-PSS
	PS256: 'PS256',
	PS384: 'PS384',
	PS512: 'PS512'
}

export type AlgorithmParameterValue = keyof typeof AlgorithmParameterValues

export const hmacAlgParams = Object.freeze({
	HS256: Object.freeze({
		hashAlg: 'sha256',
		type: 'secret',
		minKeyBytes: 32
	}),
	HS384: Object.freeze({
		hashAlg: 'sha384',
		type: 'secret',
		minKeyBytes: 48
	}),
	HS512: Object.freeze({ hashAlg: 'sha512', type: 'secret', minKeyBytes: 64 })
})

export const rsaAlgParams = Object.freeze({
	RS256: Object.freeze({
		asymmetricKeyType: 'rsa',
		hashAlg: 'sha256',
		minKeyBits: 2048,
		signKeyType: 'private',
		verifyKeyType: 'public'
	}),
	RS384: Object.freeze({
		asymmetricKeyType: 'rsa',
		hashAlg: 'sha384',
		minKeyBits: 2048,
		signKeyType: 'private',
		verifyKeyType: 'public'
	}),
	RS512: Object.freeze({
		asymmetricKeyType: 'rsa',
		hashAlg: 'sha512',
		minKeyBits: 2048,
		signKeyType: 'private',
		verifyKeyType: 'public'
	})
})

export const ecdsaAlgParams = Object.freeze({
	ES256: Object.freeze({
		asymmetricKeyType: 'ec',
		hashAlg: 'sha256',
		namedCurve: 'prime256v1',
		signKeyType: 'private',
		verifyKeyType: 'public',
		signatureBytes: 64
	}),
	ES384: Object.freeze({
		asymmetricKeyType: 'ec',
		hashAlg: 'sha384',
		namedCurve: 'secp384r1',
		signKeyType: 'private',
		verifyKeyType: 'public',
		signatureBytes: 96
	}),
	ES512: Object.freeze({
		asymmetricKeyType: 'ec',
		hashAlg: 'sha512',
		namedCurve: 'secp521r1',
		signKeyType: 'private',
		verifyKeyType: 'public',
		signatureBytes: 132
	})
})

export const rsaPssAlgParams = Object.freeze({
	PS256: Object.freeze({
		asymmetricKeyType: 'rsa-pss',
		hashAlg: 'sha256',
		minKeyBits: 2048,
		signKeyType: 'private',
		verifyKeyType: 'public'
	}),
	PS384: Object.freeze({
		asymmetricKeyType: 'rsa-pss',
		hashAlg: 'sha384',
		minKeyBits: 2048,
		signKeyType: 'private',
		verifyKeyType: 'public'
	}),
	PS512: Object.freeze({
		asymmetricKeyType: 'rsa-pss',
		hashAlg: 'sha512',
		minKeyBits: 2048,
		signKeyType: 'private',
		verifyKeyType: 'public'
	})
})
