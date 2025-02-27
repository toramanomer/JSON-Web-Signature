export const isString = (value: unknown): value is string =>
	typeof value === 'string'

export const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === 'object' && value !== null && !Array.isArray(value)

/**
 * Checks if two objects have no common keys
 */
export const isDisjoint = (
	obj1?: Record<string, unknown>,
	obj2?: Record<string, unknown>
): boolean => {
	// If either object is missing, they are disjoint by definition
	if (!obj1 || !obj2) return true

	const keys1 = Object.keys(obj1)
	const keys2 = Object.keys(obj2)

	// If the sum of individual key counts equals the size of their union,
	// then there are no common keys
	const union = new Set([...keys1, ...keys2])
	return keys1.length + keys2.length === union.size
}
