export type PEM<T extends string> = {
  [Key in T]: string
}

export type JWK = {
  alg: string
  kid: string
  kty: string
  e: string
  n: string
  use: string
  x5t?: string
  x5c?: string[]
}

export type Secret = string | JWK | JWK[] | PEM<string>
