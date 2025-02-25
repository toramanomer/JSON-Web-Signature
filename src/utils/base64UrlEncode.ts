import { Buffer } from 'node:buffer'

/**
 * base64url encodes a string or buffer
 */
export const base64UrlEncode = (input: string | Buffer): string => {
	const buf = Buffer.isBuffer(input) ? input : Buffer.from(input)
	return buf.toString('base64url')
}
