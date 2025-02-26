import { createVerify, KeyObject } from 'node:crypto'
import { EcdsaAlgorithm, ecdsaParams } from './params'

interface VerifyEcdsaInput {
	key: KeyObject
	algorithm: EcdsaAlgorithm
	signingInput: string
	signature: Buffer
}

export const verifyEcdsa = (input: VerifyEcdsaInput): boolean => {
	const { key, algorithm, signingInput, signature } = input
	const {
		hashAlg,
		namedCurve,
		verifyKeyType,
		asymmetricKeyType,
		signatureBytes
	} = ecdsaParams[algorithm]

	if (key.type !== verifyKeyType)
		throw new Error(
			`Invalid key type for ${algorithm}. Expected "${verifyKeyType}", got "${key.type}".`
		)

	if (key.asymmetricKeyType !== asymmetricKeyType)
		throw new Error(
			`Invalid key type for ${algorithm}. Expected "${asymmetricKeyType}", got "${key.asymmetricKeyType}".`
		)

	if (key.asymmetricKeyDetails?.namedCurve !== namedCurve)
		throw new Error(`Invalid curve for ${algorithm}.`)

	if (signature.length !== signatureBytes)
		throw new Error(`Signature is not 64 bytes`)

	return createVerify(hashAlg).update(signingInput).verify(key, signature)
}
