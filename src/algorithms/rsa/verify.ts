import { createVerify, KeyObject } from 'node:crypto'
import { RsaAlgorithm, rsaParams } from './params'

interface VerifyRsaInput {
	key: KeyObject
	algorithm: RsaAlgorithm
	signingInput: string
	signature: Buffer
}

export const verifyRsa = ({
	key,
	algorithm,
	signingInput,
	signature
}: VerifyRsaInput): boolean => {
	const { asymmetricKeyType, hashAlg, minKeyBits, verifyKeyType } =
		rsaParams[algorithm]

	if (key.type !== verifyKeyType)
		throw new Error(
			`Invalid key type for ${algorithm}. Expected "${verifyKeyType}", got "${key.type}".`
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

	return createVerify(hashAlg).update(signingInput).verify(key, signature)
}
