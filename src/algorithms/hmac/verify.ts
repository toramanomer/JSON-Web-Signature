import { createHmac, timingSafeEqual, type KeyObject } from 'node:crypto'

import { hmacParams, type HmacAlgorithm } from './params'
import { validateHmacKey } from './validateKey'

interface VerifyHmacInput {
	algorithm: HmacAlgorithm
	key: KeyObject
	signature: Buffer
	signingInput: string
}

export const verifyHmac = ({
	algorithm,
	key,
	signature,
	signingInput
}: VerifyHmacInput): boolean => {
	validateHmacKey({ key, algorithm })

	const { hashAlg } = hmacParams[algorithm]

	const expectedSignature = createHmac(hashAlg, key)
		.update(signingInput)
		.digest()

	// Constant-time comparison to prevent timing attacks
	return timingSafeEqual(signature, expectedSignature)
}
