import { type Algorithm } from '@/algorithms/algorithms'
import { JWSHeaderParameters } from '@/types/jws'
import { isString } from '../common/isString'
import { isJsonObject } from '../common/isJsonObject'

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
		throw new Error('EC JWK must contain a "crv" (Curve) parameter')

	if (!ALLOWED_EC_CURVES.includes(jwk.crv as any))
		throw new Error(
			`Invalid curve: ${jwk.crv}. Must be one of: ${ALLOWED_EC_CURVES.join(', ')}`
		)

	if (!isString(jwk.x))
		throw new Error('EC JWK must contain an "x" coordinate parameter')

	if (!isString(jwk.y))
		throw new Error('EC JWK must contain a "y" coordinate parameter')
}

const validateRSAKey = (jwk: Record<string, unknown>) => {
	if (!isString(jwk.n))
		throw new Error('RSA JWK must contain a "n" (modulus) parameter')

	if (!isString(jwk.e))
		throw new Error('RSA JWK must contain an "e" (exponent) parameter')
}

const validateNoPrivateParams = (jwk: Record<string, unknown>) => {
	const foundPrivateParams = PRIVATE_KEY_PARAMS.filter(param => param in jwk)
	if (foundPrivateParams.length > 0) {
		throw new Error(
			`JWK must not contain private key parameters: ${foundPrivateParams.join(', ')}`
		)
	}
}

const validateKeyTypeForAlg = (kty: string, alg: Algorithm) => {
	switch (alg) {
		case 'HS256':
		case 'HS384':
		case 'HS512':
			throw new Error('JWK must not be present for HMAC algorithms')

		case 'RS256':
		case 'RS384':
		case 'RS512':
		case 'PS256':
		case 'PS384':
		case 'PS512':
			if (kty !== 'RSA')
				throw new Error(`Algorithm ${alg} requires an RSA key type`)
			break

		case 'ES256':
		case 'ES384':
		case 'ES512':
			if (kty !== 'EC')
				throw new Error(`Algorithm ${alg} requires an EC key type`)
			break

		default:
			throw new Error(`Unsupported algorithm: ${alg}`)
	}
}

export const validateJwk = ({
	jwk,
	alg
}: Pick<JWSHeaderParameters, 'jwk' | 'alg'>) => {
	if (!jwk) return // jwk is optional

	if (!isJsonObject(jwk))
		throw new Error('The "jwk" header parameter must be a JSON object')

	if (!isString(jwk.kty))
		throw new Error('JWK must contain a "kty" (Key Type) parameter')

	const validatedJwk = jwk

	validateNoPrivateParams(jwk)
	validateKeyTypeForAlg(validatedJwk.kty as string, alg)

	switch (validatedJwk.kty) {
		case 'EC':
			validateECKey(validatedJwk)
			break
		case 'RSA':
			validateRSAKey(validatedJwk)
			break
		case 'oct':
			throw new Error('JWK must not be of type "oct" (symmetric key)')
		default:
			throw new Error(`Unsupported key type: ${validatedJwk.kty}`)
	}
}
