import { createSign, KeyObject } from 'node:crypto'
import { EcdsaAlgorithm, ecdsaParams } from './params'

interface SignEcdsaInput {
	key: KeyObject
	algorithm: EcdsaAlgorithm
	signingInput: string
}

export const signEcdsa = (input: SignEcdsaInput): Buffer => {
	const { key, algorithm, signingInput } = input
	const { hashAlg, namedCurve, signKeyType, asymmetricKeyType } =
		ecdsaParams[algorithm]

	if (key.type !== signKeyType)
		throw new Error(
			`Invalid key type for ${algorithm}. Expected "${signKeyType}", got "${key.type}".`
		)

	if (key.asymmetricKeyType !== asymmetricKeyType)
		throw new Error(
			`Invalid key type for ${algorithm}. Expected "${asymmetricKeyType}", got "${key.asymmetricKeyType}".`
		)

	if (key.asymmetricKeyDetails?.namedCurve !== namedCurve)
		throw new Error(`Invalid curve for ${algorithm}.`)

	return createSign(hashAlg).update(signingInput).sign(key)
}
