type JsonPrimative = string | number | boolean | null
type JsonArray = JsonPrimative | JsonComposite[]
type JsonObject = { [key: string]: JsonPrimative | JsonComposite }
type JsonComposite = JsonArray | JsonObject

export const isJsonValue = (value: unknown): boolean => {
	if (value === null) return true

	if (typeof value === 'string' || typeof value === 'boolean') return true

	if (typeof value === 'number') return !isNaN(value) && isFinite(value)

	if (typeof value === 'object') {
		if (Array.isArray(value)) return value.every(item => isJsonValue(item))

		return isJsonObject(value)
	}

	return false
}

export const isJsonObject = (value: unknown): value is JsonObject => {
	if (typeof value !== 'object' || value === null) return false

	if (Array.isArray(value)) return false

	if (Object.getPrototypeOf(value) !== Object.prototype) return false

	return Object.entries(value).every(([key, val]) => {
		if (typeof key !== 'string') return false

		return isJsonValue(val)
	})
}
