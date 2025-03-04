import { createVerify, type KeyObject } from 'node:crypto'

import { rsaParams, type RsaAlgorithm } from './params'
import { validateRsaKey } from './validateKey'

interface VerifyRsaInput {
	algorithm: RsaAlgorithm
	key: KeyObject
	signature: Buffer
	signingInput: string
}

export const verifyRsa = ({
	algorithm,
	key,
	signature,
	signingInput
}: VerifyRsaInput): boolean => {
	validateRsaKey({ algorithm, key, usage: 'verify' })

	const { hashAlg } = rsaParams[algorithm]

	return createVerify(hashAlg).update(signingInput).verify(key, signature)
}
