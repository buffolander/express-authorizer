import { Union, Literal, Static } from 'runtypes'
import { authentication$API_GATEWAY, authentication$SERVER } from '../constants'

export const AuthenticationAgentEnum = Union(
  Literal(authentication$API_GATEWAY),
  Literal(authentication$SERVER),
)
export type AuthenticationAgent = Static<typeof AuthenticationAgentEnum>
