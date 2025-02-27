import { type JWSHeaderParameters } from '@/types/jws'
import { isString } from '@/validation/common/typeChecks'

export const validateCty = ({ cty }: Pick<JWSHeaderParameters, 'cty'>) => {
	if (!cty) return

	if (!isString(cty))
		throw new Error('The "cty" header parameter must be a string')
}
