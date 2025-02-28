export const isString = (value: unknown): value is string =>
	typeof value === 'string'

const isNumber = (value: unknown): value is number =>
	typeof value === 'number' && !isNaN(value) && isFinite(value)

const isJsonValue = (value: unknown) => {
	switch (true) {
		case isString(value):
		case isNumber(value):
		case typeof value === 'boolean':
		case value === null:
			return true
	}

	if (Array.isArray(value)) {
		for (const item of value)
			if (isJsonValue(item)) continue
			else return false
		return true
	}

	return isObject(value)
}

type JsonPrimative = string | number | boolean | null
type JsonArray = JsonPrimative | JsonComposite[]
type JsonObject = { [key: string]: JsonPrimative | JsonComposite }
type JsonComposite = JsonArray | JsonObject

export const isObject = (value: unknown): value is JsonObject => {
	if (
		typeof value !== 'object' ||
		value === null ||
		Object.getPrototypeOf(value) !== Object.prototype
	)
		return false

	for (const v of Object.values(value))
		if (isJsonValue(v)) continue
		else return false

	return true
}

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
