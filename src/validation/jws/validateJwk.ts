import type { Algorithm } from 'src/algorithms/algorithms.js'
import type { JWSHeaderParameters } from 'src/types/jws.js'
import { isString } from '../common/isString.js'
import { isJsonObject } from '../common/isJsonObject.js'
import { JWSError } from '../../errors/JWSError.js'

const ALLOWED_EC_CURVES = ['P-256', 'P-384', 'P-521'] as const

const PRIVATE_KEY_PARAMS = [
	'd',
	'p',
	'q',
	'dp',
	'dq',
	'qi',
	'k',
	'oth'
] as const

const validateECKey = (jwk: Record<string, unknown>) => {
	if (!isString(jwk.crv))
		throw JWSError.headerParamInvalid(
			'EC JWK must contain a "crv" (Curve) parameter'
		)

	if (!ALLOWED_EC_CURVES.includes(jwk.crv as any))
		throw JWSError.headerParamInvalid(
			`Invalid curve: ${jwk.crv}. Must be one of: ${ALLOWED_EC_CURVES.join(', ')}`
		)

	if (!isString(jwk.x))
		throw JWSError.headerParamInvalid(
			'EC JWK must contain an "x" coordinate parameter'
		)

	if (!isString(jwk.y))
		throw JWSError.headerParamInvalid(
			'EC JWK must contain a "y" coordinate parameter'
		)
}

const validateRSAKey = (jwk: Record<string, unknown>) => {
	if (!isString(jwk.n))
		throw JWSError.headerParamInvalid(
			'RSA JWK must contain a "n" (modulus) parameter'
		)

	if (!isString(jwk.e))
		throw JWSError.headerParamInvalid(
			'RSA JWK must contain an "e" (exponent) parameter'
		)
}

const validateNoPrivateParams = (jwk: Record<string, unknown>) => {
	const privateParams = PRIVATE_KEY_PARAMS.filter(param => param in jwk)
	if (privateParams.length > 0)
		throw JWSError.headerParamInvalid(
			`JWK contains private key parameters: ${privateParams.join(', ')}`
		)
}

const validateKeyTypeForAlg = (kty: string, alg: Algorithm) => {
	if (!['RSA', 'EC'].includes(kty))
		throw JWSError.headerParamInvalid(
			`Invalid key type. Must be one of: RSA, EC`
		)

	// RSA algorithms
	if (['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'].includes(alg)) {
		if (kty !== 'RSA')
			throw JWSError.headerParamInvalid(
				`Algorithm ${alg} requires an RSA key (kty: "RSA"), but got "${kty}"`
			)
		return
	}

	// ECDSA algorithms
	if (['ES256', 'ES384', 'ES512'].includes(alg)) {
		if (kty !== 'EC')
			throw JWSError.headerParamInvalid(
				`Algorithm ${alg} requires an EC key (kty: "EC"), but got "${kty}"`
			)
		return
	}
}

export const validateJwk = (header: JWSHeaderParameters) => {
	if (!('jwk' in header)) return
	const { jwk, alg } = header

	if (!isJsonObject(jwk))
		throw JWSError.headerParamInvalid(
			'The "jwk" header parameter must be a JSON object'
		)

	if (!isString(jwk.kty))
		throw JWSError.headerParamInvalid(
			'JWK must contain a "kty" (Key Type) parameter'
		)

	// Validate key type based on algorithm
	validateKeyTypeForAlg(jwk.kty, alg)

	// Validate key based on type
	if (jwk.kty === 'EC') validateECKey(jwk)
	else if (jwk.kty === 'RSA') validateRSAKey(jwk)

	// Ensure no private key parameters are included
	validateNoPrivateParams(jwk)
}
