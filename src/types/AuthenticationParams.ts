import { TokenVerification } from './TokenVerification'
import { Secret } from './Secrets'

export type AuthenticationParams = {
  method: TokenVerification
  secret: Secret
  secret_refresh_interval?: number
}
