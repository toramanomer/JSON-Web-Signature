import type { KeyObject } from 'node:crypto'

import { rsaPssParams, type RsaPssAlgorithm } from './params'
import { InvalidKeyError } from '../InvalidKeyError'

interface ValidateRsaPssKeyInput {
	algorithm: RsaPssAlgorithm
	key: KeyObject
	usage: 'sign' | 'verify'
}

export const validateRsaPssKey = ({
	algorithm,
	key,
	usage
}: ValidateRsaPssKeyInput) => {
	const { asymmetricKeyType, minKeyBits, signKeyType, verifyKeyType } =
		rsaPssParams[algorithm]

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
