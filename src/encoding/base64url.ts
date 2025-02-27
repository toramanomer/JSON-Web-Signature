import { Buffer } from 'node:buffer'

export const base64UrlEncode = (data: Buffer | string) => {
	const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data)
	return buffer.toString('base64url')
}

export const base64UrlDecode = (str: string) => Buffer.from(str, 'base64url')
