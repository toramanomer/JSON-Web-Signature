import { createVerify, type KeyObject } from 'node:crypto'

import { ecdsaParams, type EcdsaAlgorithm } from './params'
import { validateEcdsaKey } from './validateKey'

interface VerifyEcdsaInput {
	algorithm: EcdsaAlgorithm
	key: KeyObject
	signature: Buffer
	signingInput: string
}

export const verifyEcdsa = ({
	algorithm,
	key,
	signature,
	signingInput
}: VerifyEcdsaInput): boolean => {
	validateEcdsaKey({ algorithm, key, usage: 'verify' })

	const { hashAlg, signatureBytes } = ecdsaParams[algorithm]

	if (signature.length !== signatureBytes)
		throw new Error(`Signature is not 64 bytes`)

	return createVerify(hashAlg).update(signingInput).verify(key, signature)
}
