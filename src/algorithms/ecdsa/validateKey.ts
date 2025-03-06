import type { KeyObject } from 'node:crypto'

import { KeyError } from 'src/errors/KeyError.js'
import { ecdsaParams, type EcdsaAlgorithm } from './params.js'

interface ValidateEcdsaKeyInput {
	algorithm: EcdsaAlgorithm
	key: KeyObject
	usage: 'sign' | 'verify'
}

export const validateEcdsaKey = ({
	algorithm,
	key,
	usage
}: ValidateEcdsaKeyInput) => {
	const { asymmetricKeyType, namedCurve, signKeyType, verifyKeyType } =
		ecdsaParams[algorithm]

	const expectedKeyType = usage === 'sign' ? signKeyType : verifyKeyType

	if (key.type !== expectedKeyType)
		throw KeyError.invalidType(algorithm, expectedKeyType)

	if (key.asymmetricKeyType !== asymmetricKeyType)
		throw KeyError.invalidAsymmetricKeyType(algorithm, asymmetricKeyType)

	if (key.asymmetricKeyDetails?.namedCurve !== namedCurve)
		throw KeyError.invalidCurve(algorithm)
}
