import { ecdsaParams } from './ecdsa/params.js'
import { hmacParams } from './hmac/params.js'
import { rsaParams } from './rsa/params.js'
import { rsaPssParams } from './rsa-pss/params.js'

import { keys } from '../utils/object.js'

export const algorithms = Object.freeze([
	...keys(ecdsaParams),
	...keys(hmacParams),
	...keys(rsaParams),
	...keys(rsaPssParams)
])

export type Algorithm = (typeof algorithms)[number]
