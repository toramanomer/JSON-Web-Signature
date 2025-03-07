import type { KeyObject } from 'node:crypto'

import type { Algorithm } from 'src/algorithms/algorithms.js'
import { isObject } from 'src/validation/common/isObject.js'

import { isString } from 'src/validation/common/isString.js'
import type { createGeneralJws } from './createJws.js'

type VerifyGeneralJwsInput = {
	jws: ReturnType<typeof createGeneralJws>
	key: KeyObject
	allowedAlgorithms?: Algorithm[]
}

export const verifyGeneralJws = (input: VerifyGeneralJwsInput) => {
	if (!isObject(input)) throw new TypeError('The "input" must be an object')
}
