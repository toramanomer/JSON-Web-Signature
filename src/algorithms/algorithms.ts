import { hmacParams } from './hmac/params'
import { rsaParams } from './rsa/params'
import { ecdsaParams } from './ecdsa/params'
import { rsaPssParams } from './rsa-pss/params'

import { keys } from '../utils/object'

export const algorithms = Object.freeze([
	...keys(hmacParams),
	...keys(rsaParams),
	...keys(ecdsaParams),
	...keys(rsaPssParams)
])

export type Algorithm = (typeof algorithms)[number]
