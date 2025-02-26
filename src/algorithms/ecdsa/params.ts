export const ecdsaParams = Object.freeze({
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

export type EcdsaAlgorithm = keyof typeof ecdsaParams
