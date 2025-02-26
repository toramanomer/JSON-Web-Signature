import { createHmac, KeyObject, timingSafeEqual } from 'node:crypto'
import { HmacAlgorithm, hmacParams } from './params'

interface VerifyHmacInput {
	key: KeyObject
	algorithm: HmacAlgorithm
	signingInput: string
	signature: Buffer
}

export const verifyHmac = ({
	key,
	algorithm,
	signingInput,
	signature
}: VerifyHmacInput): boolean => {
	const { hashAlg, type, minKeyBytes } = hmacParams[algorithm]

	if (key.type !== type)
		throw new Error(
			`Invalid key type for ${algorithm}. Expected "${type}", got "${key.type}".`
		)

	if (!key.symmetricKeySize || key.symmetricKeySize < minKeyBytes)
		throw new Error(
			`Key is too short for ${algorithm}. Expected at least ${minKeyBytes} bytes, got ${key.symmetricKeySize} bytes.`
		)

	const expectedSignature = createHmac(hashAlg, key)
		.update(signingInput)
		.digest()

	// Constant-time comparison to prevent timing attacks
	return timingSafeEqual(signature, expectedSignature)
}
