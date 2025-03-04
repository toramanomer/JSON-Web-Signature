import { constants, createVerify, type KeyObject } from 'node:crypto'

import { rsaPssParams, type RsaPssAlgorithm } from './params'
import { validateRsaPssKey } from './validateKey'

interface VerifyRsaPssInput {
	algorithm: RsaPssAlgorithm
	key: KeyObject
	signature: Buffer
	signingInput: string
}

export const verifyRsaPss = ({
	algorithm,
	key,
	signature,
	signingInput
}: VerifyRsaPssInput): boolean => {
	validateRsaPssKey({ algorithm, key, usage: 'verify' })

	const { hashAlg } = rsaPssParams[algorithm]

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
