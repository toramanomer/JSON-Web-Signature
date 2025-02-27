import { type JWSHeaderParameters } from '@/types/jws'
import { isObject } from './isObject'

const ecParams = { crv: ['P-256', 'P-384', 'P-521'] }

const validateECJwk = (jwk: Record<string, unknown>) => {
	const { crv, x, y, d } = jwk

	if (!ecParams.crv.includes(crv as string))
		throw new Error(
			`Invalid curve: ${crv}, must be one of ${ecParams.crv.join(', ')}`
		)

	if (typeof x !== 'string' || typeof y !== 'string')
		throw new Error('The JWK must contain a "x" and "y" parameter')

	if (d) throw new Error('The JWK must not contain a "d" parameter.')
}

const validateRSAJwk = (jwk: Record<string, unknown>) => {
	const { n, e, d, p, q, dp, dq, qi, oth } = jwk

	if (typeof n !== 'string' || typeof e !== 'string')
		throw new Error('The JWK must contain a "n" and "e" parameter')

	if (d) throw new Error('The JWK must not contain a "d" parameter.')

	if (p) throw new Error('The JWK must not contain a "p" parameter.')

	if (q) throw new Error('The JWK must not contain a "q" parameter.')

	if (dp) throw new Error('The JWK must not contain a "dp" parameter.')

	if (dq) throw new Error('The JWK must not contain a "dq" parameter.')

	if (qi) throw new Error('The JWK must not contain a "qi" parameter.')

	if (oth) throw new Error('The JWK must not contain a "oth" parameter.')
}

export const validateJwk = ({
	jwk,
	alg
}: Pick<JWSHeaderParameters, 'jwk' | 'alg'>) => {
	if (!jwk) return

	if (!isObject(jwk))
		throw new Error('The "jwk" header parameter must be a JSON object')

	switch (jwk.kty) {
		case 'EC':
			validateECJwk(jwk)
			break
		case 'RSA':
			validateRSAJwk(jwk)
			break
		case 'oct':
			throw new Error(
				'The JWK in the JOSE header is only for public keys.'
			)
		default:
			throw new Error(`Unsupported key type: ${jwk.kty}`)
	}

	switch (alg) {
		case 'HS256':
		case 'HS384':
		case 'HS512':
			if (jwk)
				throw new Error(
					'The "jwk" header parameter must not be present when using an HMAC-based algorithm.'
				)
			break
		case 'RS256':
		case 'RS384':
		case 'RS512':
		case 'PS256':
		case 'PS384':
		case 'PS512':
			if (jwk.kty !== 'RSA')
				throw new Error(
					'The JWK in the JOSE header must be a RSA key when using a RSASSA-PKCS1-v1_5 or RSASSA-PSS signature algorithm.'
				)
			break
		case 'ES256':
		case 'ES384':
		case 'ES512':
			if (jwk.kty !== 'EC')
				throw new Error(
					'The JWK in the JOSE header must be a EC key when using a ECDSA signature algorithm.'
				)
			break
	}
}
