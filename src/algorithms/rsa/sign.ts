import { createSign, KeyObject } from 'node:crypto'
import { RsaAlgorithm, rsaParams } from './params'

interface SignRsaInput {
	key: KeyObject
	algorithm: RsaAlgorithm
	signingInput: string
}

export const signRsa = (input: SignRsaInput): Buffer => {
	const { key, algorithm, signingInput } = input
	const { asymmetricKeyType, hashAlg, minKeyBits, signKeyType } =
		rsaParams[algorithm]

	if (key.type !== signKeyType)
		throw new Error(
			`Invalid key type for ${algorithm}. Expected "${signKeyType}", got "${key.type}".`
		)

	if (key.asymmetricKeyType !== asymmetricKeyType)
		throw new Error(
			`Invalid key type for ${algorithm}. Expected "${asymmetricKeyType}", got "${key.asymmetricKeyType}".`
		)

	const keySizeInBits = key.asymmetricKeyDetails?.modulusLength
	if (!keySizeInBits || keySizeInBits < minKeyBits) {
		throw new Error(
			`Key size for ${algorithm} is too small. Expected at least ${minKeyBits} bits, got ${keySizeInBits} bits.`
		)
	}

	return createSign(hashAlg).update(signingInput).sign(key)
}
