import { createHmac, type KeyObject } from 'node:crypto'

import { hmacParams, type HmacAlgorithm } from './params'
import { validateHmacKey } from './validateKey'

interface SignHmacInput {
	algorithm: HmacAlgorithm
	key: KeyObject
	signingInput: string
}

export const signHmac = ({
	algorithm,
	key,
	signingInput
}: SignHmacInput): Buffer => {
	validateHmacKey({ key, algorithm })

	const { hashAlg } = hmacParams[algorithm]

	return createHmac(hashAlg, key).update(signingInput).digest()
}
