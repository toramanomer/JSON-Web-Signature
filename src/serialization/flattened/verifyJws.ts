import { isKeyObject } from 'node:util/types'
import type { KeyObject } from 'node:crypto'

import { algorithms, type Algorithm } from 'src/algorithms/algorithms.js'
import type { JWSHeaderParameters, JWSProtectedHeader } from 'src/types/jws.js'
import { JWSError } from 'src/errors/JWSError.js'

import { verifySignature } from 'src/crypto/verify.js'

import { base64UrlDecode, isBase64url } from 'src/encoding/base64url.js'

import { isString } from 'src/validation/common/isString.js'
import { isObject } from 'src/validation/common/isObject.js'
import { isDisjoint } from 'src/validation/common/isDisjoint.js'
import { isJsonObject } from 'src/validation/common/isJsonObject.js'

import { validateAlg } from 'src/validation/jws/validateAlg.js'
import { validateKid } from 'src/validation/jws/validateKid.js'
import { validateJwk } from 'src/validation/jws/validateJwk.js'
import { validateJku } from 'src/validation/jws/validateJku.js'
import { validateTyp } from 'src/validation/jws/validateTyp.js'
import { validateCty } from 'src/validation/jws/validateCty.js'
import { validateCrit } from 'src/validation/jws/validateCrit.js'

export interface VerifyFlattenedJwsInput {
	/**
	 * The JWS to verify (in flattened JSON serialization format)
	 */
	readonly jws: Readonly<{
		payload: string
		protected?: string
		header?: JWSHeaderParameters
		signature: string
	}>

	readonly key: KeyObject

	/**
	 * Optional list of allowed algorithms
	 * If provided, the algorithm in the JWS header must be in this list
	 */
	readonly allowedAlgorithms?: Algorithm[]
}

export function verifyFlattenedJws(input: VerifyFlattenedJwsInput) {
	if (!isObject(input)) throw new TypeError('The "input" must be an object')

	const { jws, key, allowedAlgorithms } = input

	if (!isKeyObject(key))
		throw new TypeError('The provided key must be an instance of KeyObject')

	if (!isObject(jws))
		throw JWSError.invalidFormat('The "jws" argument must be an object')

	if (Object.hasOwn(input, 'allowedAlgorithms')) {
		if (!Array.isArray(allowedAlgorithms))
			throw new TypeError('The "allowedAlgorithms" must be an array')
		else if (allowedAlgorithms.some(algorithm => !isString(algorithm)))
			throw new TypeError(
				'The "allowedAlgorithms" must be an array of strings'
			)
		else if (new Set(allowedAlgorithms).size !== allowedAlgorithms.length)
			throw new Error(
				'The "allowedAlgorithms" must be an array of unique strings'
			)
		else if (
			allowedAlgorithms.some(algorithm => !algorithms.includes(algorithm))
		)
			throw new Error(
				'The "allowedAlgorithms" must be an array of valid algorithms'
			)
	}

	const {
		payload: encodedPayload,
		protected: encodedProtectedHeader,
		header: unprotectedHeader,
		signature: encodedSignature
	} = jws

	let protectedHeader: JWSProtectedHeader | undefined

	if (Object.hasOwn(jws, 'protected')) {
		if (!isString(encodedProtectedHeader))
			throw JWSError.invalidProtectedHeader(
				'Protected header must be a string'
			)
		else if (!isBase64url(encodedProtectedHeader))
			throw JWSError.invalidProtectedHeader(
				'Protected header must be base64url-encoded'
			)

		try {
			protectedHeader = JSON.parse(
				base64UrlDecode(encodedProtectedHeader).toString('utf8')
			)
		} catch {
			throw JWSError.invalidProtectedHeader(
				'Could not parse protected header as JSON'
			)
		}

		if (!isJsonObject(protectedHeader))
			throw JWSError.invalidProtectedHeader(
				'Protected header must be a JSON object'
			)
	}

	if (Object.hasOwn(jws, 'header')) {
		if (!isJsonObject(unprotectedHeader))
			throw JWSError.invalidUnprotectedHeader(
				'Unprotected header must be a JSON object'
			)
	}

	if (!protectedHeader && !unprotectedHeader) throw JWSError.missingHeaders()

	if (!isDisjoint(protectedHeader, unprotectedHeader))
		throw JWSError.headerParametersNotDisjoint()

	const joseHeader = { ...protectedHeader, ...unprotectedHeader }

	validateAlg(joseHeader, allowedAlgorithms)
	validateJku(joseHeader)
	validateJwk(joseHeader)
	validateKid(joseHeader)
	validateTyp(joseHeader)
	validateCty(joseHeader)
	validateCrit({ protectedHeader, unprotectedHeader })

	if (!isString(encodedPayload))
		throw JWSError.invalidPayload('Payload must be a string')
	else if (!isBase64url(encodedPayload))
		throw JWSError.invalidPayload('Payload must be base64url-encoded')

	if (!isString(encodedSignature))
		throw JWSError.invalidSignatureEncoding('Signature must be a string')
	else if (!isBase64url(encodedSignature))
		throw JWSError.invalidSignatureEncoding(
			'Signature must be base64url-encoded'
		)

	const signature = base64UrlDecode(encodedSignature)

	const signingInput =
		encodedProtectedHeader ?
			`${encodedProtectedHeader}.${encodedPayload}`
		:	`.${encodedPayload}`

	const isValid = verifySignature({
		algorithm: joseHeader.alg,
		key,
		signature,
		signingInput
	})

	if (!isValid) throw JWSError.invalidSignature()

	return {
		payload: encodedPayload,
		...(!!protectedHeader && { protected: encodedProtectedHeader }),
		...(!!unprotectedHeader && { header: unprotectedHeader }),
		signature: encodedSignature
	}
}
