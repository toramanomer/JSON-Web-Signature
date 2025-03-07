import type { Algorithm } from 'src/algorithms/algorithms.js'
import type { JWSHeaderParameters } from 'src/types/jws.js'
import { isBase64url } from 'src/encoding/base64url.js'
import { JWSError } from 'src/errors/JWSError.js'
import { isString } from '../common/isString.js'

/////////////////////////////////////////////////
// Elliptic Curve (EC)
/////////////////////////////////////////////////
const allowedCurves = ['P-256', 'P-384', 'P-521'] as const
const ecPublicParams = ['crv', 'x', 'y'] as const
const ecPrivateParams = ['d'] as const

const validateECKey = (jwk: Record<string, unknown>) => {
	if (!allowedCurves.includes(jwk.crv as any))
		throw JWSError.headerParamInvalid(
			`Invalid curve: ${jwk.crv}. Must be one of: ${allowedCurves.join(', ')}`
		)

	for (const param of ecPublicParams)
		if (!isString(jwk[param]))
			throw JWSError.headerParamInvalid(
				`"jwk" must contain a "${param}" parameter for EC keys`
			)
		else if (!isBase64url(jwk[param]))
			throw JWSError.headerParamInvalid(
				`"${param}" parameter must be a valid Base64URL-encoded string`
			)

	for (const param of ecPrivateParams)
		if (param in jwk)
			throw JWSError.headerParamInvalid(
				`"jwk" must not contain a "${param}" parameter for EC keys`
			)
}

/////////////////////////////////////////////////
// RSA
/////////////////////////////////////////////////
const rsaPublicParams = ['n', 'e'] as const
const rsaPrivateParams = ['p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'] as const

const validateRSAKey = (jwk: Record<string, unknown>) => {
	for (const param of rsaPublicParams)
		if (!isString(jwk[param]))
			throw JWSError.headerParamInvalid(
				`"jwk" must contain a "${param}" parameter for RSA keys`
			)

	for (const param of rsaPrivateParams)
		if (param in jwk)
			throw JWSError.headerParamInvalid(
				`"jwk" must not contain a "${param}" parameter for RSA keys`
			)
}

/////////////////////////////////////////////////
// Key Type
/////////////////////////////////////////////////
const allowedKeyTypes = ['RSA', 'EC'] as const

const validateKeyTypeForAlg = (kty: string, alg: Algorithm) => {
	if (!allowedKeyTypes.includes(kty as any))
		throw JWSError.headerParamInvalid(
			`Invalid key type. Must be one of: ${allowedKeyTypes.join(', ')}`
		)

	switch (alg) {
		case 'RS256':
		case 'RS384':
		case 'RS512':
		case 'PS256':
		case 'PS384':
		case 'PS512':
			if (kty !== 'RSA')
				throw JWSError.headerParamInvalid(
					`Algorithm ${alg} requires an RSA key (kty: "RSA")`
				)
			return
		case 'ES256':
		case 'ES384':
		case 'ES512':
			if (kty !== 'EC')
				throw JWSError.headerParamInvalid(
					`Algorithm ${alg} requires an EC key (kty: "EC")`
				)
			return
		case 'HS256':
		case 'HS384':
		case 'HS512':
			throw JWSError.headerParamInvalid(
				`"jwk" header parameter is not allowed for ${alg} algorithm`
			)

		default:
			throw JWSError.headerParamInvalid(`Unsupported algorithm: ${alg}`)
	}
}

const disAllowedKeyOpsPerUse = {
	sig: [
		'encrypt',
		'decrypt',
		'wrapKey',
		'unwrapKey',
		'deriveKey',
		'deriveBits'
	],
	enc: ['sign', 'verify']
}
type Use = keyof typeof disAllowedKeyOpsPerUse

/**
 * Validates the "jwk" (JSON Web Key) Header Parameter.
 *
 * The JWK must:
 * - Have a valid key type ("kty") matching the algorithm
 * - Include required parameters for its key type
 * - Not contain any private key parameters
 *
 * @param header - The header object containing the optional "jwk" parameter
 * @throws {JWSError} If the "jwk" parameter is present but invalid
 */
export const validateJwk = (header: JWSHeaderParameters) => {
	if (!('jwk' in header)) return
	const { jwk, alg } = header

	if (!isString(jwk?.kty))
		throw JWSError.headerParamInvalid(
			'JWK must contain a "kty" (Key Type) parameter'
		)

	if (Object.hasOwn(jwk, 'use'))
		if (!isString(jwk.use))
			throw JWSError.headerParamInvalid(
				'"use" parameter in JWK must be a string'
			)

	if (Object.hasOwn(jwk, 'key_ops'))
		if (!Array.isArray(jwk.key_ops))
			throw JWSError.headerParamInvalid(
				'"key_ops" parameter in JWK must be an array'
			)
		else if (jwk.key_ops.some(op => !isString(op)))
			throw JWSError.headerParamInvalid(
				'"key_ops" parameter in JWK must contain only strings'
			)
		else if (jwk.key_ops.length !== new Set(jwk.key_ops).size)
			throw JWSError.headerParamInvalid(
				'"key_ops" parameter in JWK must not contain duplicate values'
			)

	if (Object.hasOwn(jwk, 'use') && Object.hasOwn(jwk, 'key_ops')) {
		const disallowedOps = disAllowedKeyOpsPerUse[jwk.use as Use]
		if (
			disallowedOps &&
			jwk.key_ops.some((op: any) => disallowedOps.includes(op))
		)
			throw JWSError.headerParamInvalid(
				`"${jwk.use}" use does not allow the following key operations: ${disallowedOps.join(', ')}`
			)
	}

	validateKeyTypeForAlg(jwk.kty, alg)

	if (jwk.kty === 'EC') validateECKey(jwk)
	else if (jwk.kty === 'RSA') validateRSAKey(jwk)
}
