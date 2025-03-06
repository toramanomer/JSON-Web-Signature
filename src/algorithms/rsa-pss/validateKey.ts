import type { KeyObject } from 'node:crypto'

import { KeyError } from 'src/errors/KeyError.js'
import { rsaPssParams, type RsaPssAlgorithm } from './params.js'

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
		throw KeyError.invalidType(algorithm, expectedKeyType)

	if (key.asymmetricKeyType !== asymmetricKeyType)
		throw KeyError.invalidAsymmetricKeyType(algorithm, asymmetricKeyType)

	const keySizeInBits = key.asymmetricKeyDetails?.modulusLength
	if (!keySizeInBits || keySizeInBits < minKeyBits)
		throw KeyError.invalidSize(algorithm, minKeyBits / 8)
}
