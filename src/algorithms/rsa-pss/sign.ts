import { constants, createSign, type KeyObject } from 'node:crypto'

import { rsaPssParams, type RsaPssAlgorithm } from './params'
import { validateRsaPssKey } from './validateKey'

interface SignRsaPssInput {
	algorithm: RsaPssAlgorithm
	key: KeyObject
	signingInput: string
}

export const signRsaPss = ({
	algorithm,
	key,
	signingInput
}: SignRsaPssInput): Buffer => {
	validateRsaPssKey({ algorithm, key, usage: 'sign' })

	const { hashAlg } = rsaPssParams[algorithm]

	return createSign(hashAlg)
		.update(signingInput)
		.sign({
			key,
			padding: constants.RSA_PKCS1_PSS_PADDING,
			saltLength: parseInt(algorithm.slice(2)) / 8
		})
}
