import type { KeyObject } from 'node:crypto'

import { KeyError } from 'src/errors/KeyError.js'
import { hmacParams, type HmacAlgorithm } from './params.js'

interface ValidateHmacKeyInput {
	algorithm: HmacAlgorithm
	key: KeyObject
}

export const validateHmacKey = ({ algorithm, key }: ValidateHmacKeyInput) => {
	const { type, minKeyBytes } = hmacParams[algorithm]

	if (key.type !== type) throw KeyError.invalidType(algorithm, type)

	if (!key.symmetricKeySize || key.symmetricKeySize < minKeyBytes)
		throw KeyError.invalidSize(algorithm, minKeyBytes)
}
