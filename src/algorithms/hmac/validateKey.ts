import type { KeyObject } from 'node:crypto'

import { InvalidKeyError } from '../InvalidKeyError.js'
import { hmacParams, type HmacAlgorithm } from './params.js'

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
