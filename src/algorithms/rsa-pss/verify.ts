import { constants, createVerify, KeyObject } from 'node:crypto'

import { RsaPssAlgorithm, rsaPssParams } from './params'

interface VerifyRsaPssInput {
	key: KeyObject
	algorithm: RsaPssAlgorithm
	signingInput: string
	signature: Buffer
}

export const verifyRsaPss = ({
	key,
	algorithm,
	signingInput,
	signature
}: VerifyRsaPssInput): boolean => {
	const { hashAlg, minKeyBits, verifyKeyType, asymmetricKeyType } =
		rsaPssParams[algorithm]

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

	return createVerify(hashAlg)
		.update(signingInput)
		.verify(
			{
				key,
				padding: constants.RSA_PKCS1_PSS_PADDING,
				saltLength: parseInt(algorithm.slice(2)) / 8
			},
			signature
		)
}
