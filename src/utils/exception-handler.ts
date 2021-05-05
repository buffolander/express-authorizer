export const exceptionHandler = (
  type: 'REQUIRED_PROP' | 'REQUIRED_CONDITIONAL' | 'INVALID_ENUM' | 'INVALID_TYPE' | 'INVALID_METHOD' | 'IGNORED_PROP' | 'DEFAULT_BEHAVIOR',
  target: string,
  enums?: (string[] | undefined),
  freeText?: (string | undefined)
) => {
  switch (type) {
    case 'DEFAULT_BEHAVIOR':
      return `"${target}" is undefined. Default behavor is ${freeText}`
    case 'IGNORED_PROP':
      return `Ignored argument (or property) "${target}" ${freeText || ''}`
    case 'INVALID_ENUM':
      return `Property "${target}" accepts values: ${enums?.join(', ')}`
    case 'INVALID_METHOD':
      return `Invalid method "${target}" ${freeText}`
    case 'INVALID_TYPE':
        return `Invalid type on argument (or property) "${target}" ${freeText || ''}`
    case 'REQUIRED_CONDITIONAL':
      return `Required property "${target}" when "${freeText}" is declared`
    case 'REQUIRED_PROP':
      return `Required property "${target}"`
    default:
      return undefined
  }
}
