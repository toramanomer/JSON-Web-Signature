export const rsaParams = Object.freeze({
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

export type RsaAlgorithm = keyof typeof rsaParams
