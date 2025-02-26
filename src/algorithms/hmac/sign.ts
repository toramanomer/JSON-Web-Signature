import { createHmac, KeyObject } from 'node:crypto'

import { hmacParams, type HmacAlgorithm } from './params'

interface SignHmacInput {
	key: KeyObject
	algorithm: HmacAlgorithm
	signingInput: string
}

export const signHmac = ({
	key,
	algorithm,
	signingInput
}: SignHmacInput): Buffer => {
	const { hashAlg, type, minKeyBytes } = hmacParams[algorithm]

	if (key.type !== type)
		throw new Error(
			`Invalid key type for ${algorithm}. Expected "${type}", got "${key.type}".`
		)

	if (!key.symmetricKeySize || key.symmetricKeySize < minKeyBytes)
		throw new Error(
			`Key is too short for ${algorithm}. Expected at least ${minKeyBytes} bytes, got ${key.symmetricKeySize} bytes.`
		)

	return createHmac(hashAlg, key).update(signingInput).digest()
}
