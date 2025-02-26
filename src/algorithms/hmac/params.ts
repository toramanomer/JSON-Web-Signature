export const hmacParams = Object.freeze({
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

export type HmacAlgorithm = keyof typeof hmacParams
