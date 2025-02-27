import { type JWSHeaderParameters } from '@/types/jws'
import { isString } from '@/validation/common/typeChecks'

export const validateTyp = ({ typ }: Pick<JWSHeaderParameters, 'typ'>) => {
	if (!typ) return

	if (!isString(typ))
		throw new Error('The "typ" header parameter must be a string')
}
