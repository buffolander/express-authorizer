import { Union, Literal, Static } from 'runtypes'
import { tokenverify$JWK, tokenverify$PEM, tokenverify$PLAIN_TEXT } from '../constants'

export const TokenVerificationEnum = Union(
  Literal(tokenverify$JWK),
  Literal(tokenverify$PEM),
  Literal(tokenverify$PLAIN_TEXT),
)
export type TokenVerification = Static<typeof TokenVerificationEnum>
