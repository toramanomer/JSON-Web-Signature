export const rsaPssParams = Object.freeze({
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

export type RsaPssAlgorithm = keyof typeof rsaPssParams
