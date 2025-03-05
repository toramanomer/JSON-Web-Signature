import { createSign, type KeyObject } from 'node:crypto'

import { rsaParams, type RsaAlgorithm } from './params.js'
import { validateRsaKey } from './validateKey.js'

interface SignRsaInput {
	algorithm: RsaAlgorithm
	key: KeyObject
	signingInput: string
}

export const signRsa = ({
	algorithm,
	key,
	signingInput
}: SignRsaInput): Buffer => {
	validateRsaKey({ algorithm, key, usage: 'sign' })

	const { hashAlg } = rsaParams[algorithm]

	return createSign(hashAlg).update(signingInput).sign(key)
}
