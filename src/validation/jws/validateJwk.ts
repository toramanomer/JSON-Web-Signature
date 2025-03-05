import type { Algorithm } from 'src/algorithms/algorithms.js'
import type { JWSHeaderParameters } from 'src/types/jws.js'
import { isString } from '../common/isString.js'
import { isJsonObject } from '../common/isJsonObject.js'
import { InvalidJWSHeaderParam } from './InvalidJWSHeaderParam.js'

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
		throw new InvalidJWSHeaderParam(
			'EC JWK must contain a "crv" (Curve) parameter',
			'jwk',
			'JWK_EC_MISSING_CRV'
		)

	if (!ALLOWED_EC_CURVES.includes(jwk.crv as any))
		throw new InvalidJWSHeaderParam(
			`Invalid curve: ${jwk.crv}. Must be one of: ${ALLOWED_EC_CURVES.join(', ')}`,
			'jwk',
			'JWK_EC_INVALID_CURVE'
		)

	if (!isString(jwk.x))
		throw new InvalidJWSHeaderParam(
			'EC JWK must contain an "x" coordinate parameter',
			'jwk',
			'JWK_EC_MISSING_X'
		)

	if (!isString(jwk.y))
		throw new InvalidJWSHeaderParam(
			'EC JWK must contain a "y" coordinate parameter',
			'jwk',
			'JWK_EC_MISSING_Y'
		)
}

const validateRSAKey = (jwk: Record<string, unknown>) => {
	if (!isString(jwk.n))
		throw new InvalidJWSHeaderParam(
			'RSA JWK must contain a "n" (modulus) parameter',
			'jwk',
			'JWK_RSA_MISSING_N'
		)

	if (!isString(jwk.e))
		throw new InvalidJWSHeaderParam(
			'RSA JWK must contain an "e" (exponent) parameter',
			'jwk',
			'JWK_RSA_MISSING_E'
		)
}

const validateNoPrivateParams = (jwk: Record<string, unknown>) => {
	const privateParams = PRIVATE_KEY_PARAMS.filter(param => param in jwk)
	if (privateParams.length > 0)
		throw new InvalidJWSHeaderParam(
			`JWK contains private key parameters: ${privateParams.join(', ')}`,
			'jwk',
			'JWK_CONTAINS_PRIVATE_PARAMS'
		)
}

const validateKeyTypeForAlg = (kty: string, alg: Algorithm) => {
	if (!['RSA', 'EC'].includes(kty))
		throw new InvalidJWSHeaderParam(
			`Invalid key type. Must be one of: RSA, EC`,
			'jwk',
			'JWK_INVALID_KTY'
		)

	// RSA algorithms
	if (['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'].includes(alg)) {
		if (kty !== 'RSA')
			throw new InvalidJWSHeaderParam(
				`Algorithm ${alg} requires an RSA key (kty: "RSA"), but got "${kty}"`,
				'jwk',
				'JWK_WRONG_KEY_TYPE_FOR_ALG'
			)
		return
	}

	// ECDSA algorithms
	if (['ES256', 'ES384', 'ES512'].includes(alg)) {
		if (kty !== 'EC')
			throw new InvalidJWSHeaderParam(
				`Algorithm ${alg} requires an EC key (kty: "EC"), but got "${kty}"`,
				'jwk',
				'JWK_WRONG_KEY_TYPE_FOR_ALG'
			)
		return
	}
}

export const validateJwk = (header: JWSHeaderParameters) => {
	if (!('jwk' in header)) return
	const { jwk, alg } = header

	if (!isJsonObject(jwk))
		throw new InvalidJWSHeaderParam(
			'The "jwk" header parameter must be a JSON object',
			'jwk',
			'JWK_NOT_OBJECT'
		)

	if (!isString(jwk.kty))
		throw new InvalidJWSHeaderParam(
			'JWK must contain a "kty" (Key Type) parameter',
			'jwk',
			'JWK_MISSING_KTY'
		)

	// Validate key type based on algorithm
	validateKeyTypeForAlg(jwk.kty, alg)

	// Validate key based on type
	if (jwk.kty === 'EC') validateECKey(jwk)
	else if (jwk.kty === 'RSA') validateRSAKey(jwk)

	// Ensure no private key parameters are included
	validateNoPrivateParams(jwk)
}
