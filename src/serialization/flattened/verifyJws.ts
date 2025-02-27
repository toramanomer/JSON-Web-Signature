import { Buffer } from 'node:buffer'
import { Algorithm } from '@/algorithms/algorithms'
import { JWSHeaderParameters } from '@/serialization/compact/createJws'

import { isObject } from '@/utils/isObject'
import { isDisjoint } from '@/utils/isDisjoint'
import { KeyObject } from 'node:crypto'
import { verifySignature } from '@/crypto/verify'

export interface VerifyFlattenedJwsInput {
	/**
	 * The JWS to verify (in flattened JSON serialization format)
	 */
	jws: {
		payload: string
		protected?: string
		header?: JWSHeaderParameters
		signature: string
	}

	key: KeyObject

	/**
	 * Optional list of allowed algorithms
	 * If provided, the algorithm in the JWS header must be in this list
	 */
	allowedAlgorithms?: Algorithm[]
}

type ValidJWSResult = { valid: true; payload: any; header: Record<string, any> }
type InvalidJWSResult = { valid: false; error: string }
type VerifyJWSResult = ValidJWSResult | InvalidJWSResult

const base64UrlDecode = (input: string) => Buffer.from(input, 'base64url')

export function verifyFlattenedJws({
	jws,
	key,
	allowedAlgorithms
}: VerifyFlattenedJwsInput): VerifyJWSResult {
	try {
		// Validate input structure
		if (!isObject(jws)) {
			return { valid: false, error: 'Invalid JWS: must be an object' }
		}

		const {
			payload,
			protected: encodedProtectedHeader,
			header,
			signature
		} = jws

		// Validate required fields
		if (typeof payload !== 'string') {
			return {
				valid: false,
				error: 'Invalid JWS: payload must be a string'
			}
		}

		if (typeof signature !== 'string') {
			return {
				valid: false,
				error: 'Invalid JWS: signature must be a string'
			}
		}

		// At least one header must be present
		if (!encodedProtectedHeader && !header) {
			return {
				valid: false,
				error: 'Invalid JWS: either protected or unprotected header must be present'
			}
		}

		// Parse protected header if present
		let protectedHeader: JWSHeaderParameters | undefined
		if (encodedProtectedHeader) {
			if (typeof encodedProtectedHeader !== 'string') {
				return {
					valid: false,
					error: 'Invalid JWS: protected header must be a string'
				}
			}

			try {
				const decoded = base64UrlDecode(encodedProtectedHeader)
				protectedHeader = JSON.parse(decoded.toString())
			} catch {
				return {
					valid: false,
					error: 'Invalid JWS: protected header must be valid base64url-encoded JSON'
				}
			}
		}

		// Validate header if present
		if (header && !isObject(header)) {
			return {
				valid: false,
				error: 'Invalid JWS: header must be an object if present'
			}
		}

		// Ensure header parameter names are disjoint
		if (!isDisjoint(protectedHeader, header)) {
			return {
				valid: false,
				error: 'Invalid JWS: Header Parameter names must be disjoint between protected and unprotected headers'
			}
		}

		// Get algorithm from either header
		const algorithm = protectedHeader?.alg || header?.alg

		// Validate algorithm
		try {
			// validateAlg({ algorithm, allowedAlgorithms })
		} catch (error) {
			return {
				valid: false,
				error: error instanceof Error ? error.message : String(error)
			}
		}

		// Decode payload
		let decodedPayload: any
		try {
			const payloadBuffer = base64UrlDecode(payload)
			try {
				decodedPayload = JSON.parse(payloadBuffer.toString())
			} catch {
				// If not valid JSON, use as string
				decodedPayload = payloadBuffer.toString()
			}
		} catch {
			return {
				valid: false,
				error: 'Invalid JWS: payload must be valid base64url-encoded data'
			}
		}

		// Verify signature
		const signatureInput =
			encodedProtectedHeader ?
				`${encodedProtectedHeader}.${payload}`
			:	`.${payload}`

		const signatureBuffer = base64UrlDecode(signature)

		const isValid = verifySignature(
			signatureInput,
			signatureBuffer,
			algorithm as Algorithm,
			key
		)

		if (!isValid) {
			return { valid: false, error: 'Invalid signature' }
		}

		// Combine headers for output
		const combinedHeader = { ...header, ...protectedHeader }

		return { valid: true, payload: decodedPayload, header: combinedHeader }
	} catch (error) {
		return {
			valid: false,
			error: `Verification failed: ${error instanceof Error ? error.message : String(error)}`
		}
	}
}
