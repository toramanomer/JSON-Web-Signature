/**
 * Checks if the Header Parameter names in the protected and unprotected
 * headers are disjoint
 *
 * Only used for JSON serializations as there is no unprotected header
 * in Compact serialization
 */
export const isDisjoint = (
	protectedHeader?: Record<string, unknown>,
	unprotectedHeader?: Record<string, unknown>
): boolean => {
	// If either header is missing, they are disjoint by definition
	if (!protectedHeader || !unprotectedHeader) return true

	const protectedNames = Object.keys(protectedHeader)
	const unprotectedNames = Object.keys(unprotectedHeader)

	const union = new Set([...protectedNames, ...unprotectedNames])

	// If equal, then no common name, otherwise they are not disjoint
	return protectedNames.length + unprotectedNames.length === union.size
}
