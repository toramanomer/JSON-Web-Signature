import { createSign, type KeyObject } from 'node:crypto'

import { EcdsaAlgorithm, ecdsaParams } from './params'
import { validateEcdsaKey } from './validateKey'

interface SignEcdsaInput {
	algorithm: EcdsaAlgorithm
	key: KeyObject
	signingInput: string
}

export const signEcdsa = ({
	algorithm,
	key,
	signingInput
}: SignEcdsaInput): Buffer => {
	validateEcdsaKey({ algorithm, key, usage: 'sign' })

	const { hashAlg } = ecdsaParams[algorithm]

	return createSign(hashAlg).update(signingInput).sign(key)
}
