export const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === 'object' && !!value && !Array.isArray(value)
