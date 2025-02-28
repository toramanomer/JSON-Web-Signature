import { hmacParams } from './hmac/params'
import { rsaParams } from './rsa/params'
import { ecdsaParams } from './ecdsa/params'
import { rsaPssParams } from './rsa-pss/params'

export type Algorithm =
	| keyof typeof hmacParams
	| keyof typeof rsaParams
	| keyof typeof ecdsaParams
	| keyof typeof rsaPssParams
