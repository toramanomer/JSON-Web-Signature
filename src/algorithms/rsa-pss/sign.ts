import { constants, createSign, KeyObject } from 'node:crypto'
import { RsaPssAlgorithm, rsaPssParams } from './params'

interface SignRsaPssInput {
	key: KeyObject
	algorithm: RsaPssAlgorithm
	signingInput: string
}

export const signRsaPss = ({
	key,
	algorithm,
	signingInput
}: SignRsaPssInput): Buffer => {
	const { hashAlg, minKeyBits, signKeyType, asymmetricKeyType } =
		rsaPssParams[algorithm]

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

	return createSign(hashAlg)
		.update(signingInput)
		.sign({
			key,
			padding: constants.RSA_PKCS1_PSS_PADDING,
			saltLength: parseInt(algorithm.slice(2)) / 8
		})
}
