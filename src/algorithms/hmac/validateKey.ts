import type { KeyObject } from 'node:crypto'

import { hmacParams, type HmacAlgorithm } from './params'
import { InvalidKeyError } from '../InvalidKeyError'

interface ValidateHmacKeyInput {
	algorithm: HmacAlgorithm
	key: KeyObject
}

export const validateHmacKey = ({ algorithm, key }: ValidateHmacKeyInput) => {
	const { type, minKeyBytes } = hmacParams[algorithm]

	if (key.type !== type) throw InvalidKeyError.invalidType(algorithm, type)

	if (!key.symmetricKeySize || key.symmetricKeySize < minKeyBytes)
		throw InvalidKeyError.invalidSize(algorithm, minKeyBytes)
}
