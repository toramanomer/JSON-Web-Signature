import type { KeyObject } from 'node:crypto'

import { rsaParams, type RsaAlgorithm } from './params'
import { InvalidKeyError } from '../InvalidKeyError'

interface ValidateRsaKeyInput {
	algorithm: RsaAlgorithm
	key: KeyObject
	usage: 'sign' | 'verify'
}

export const validateRsaKey = ({
	algorithm,
	key,
	usage
}: ValidateRsaKeyInput) => {
	const { asymmetricKeyType, minKeyBits, signKeyType, verifyKeyType } =
		rsaParams[algorithm]

	const expectedKeyType = usage === 'sign' ? signKeyType : verifyKeyType

	if (key.type !== expectedKeyType)
		throw InvalidKeyError.invalidType(algorithm, expectedKeyType)

	if (key.asymmetricKeyType !== asymmetricKeyType)
		throw InvalidKeyError.invalidAsymmetricKeyType(
			algorithm,
			asymmetricKeyType
		)

	const keySizeInBits = key.asymmetricKeyDetails?.modulusLength
	if (!keySizeInBits || keySizeInBits < minKeyBits)
		throw InvalidKeyError.invalidSize(algorithm, minKeyBits / 8)
}
