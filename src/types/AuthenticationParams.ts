import { TokenVerification } from './TokenVerification'
import { Secret } from './Secrets'

export type AuthenticationParams = {
  secret: Secret
  secret_type: TokenVerification
  secret_refresh_interval?: number
  audience?: string
  issuer?: string
}
