import axios from 'axios'
import * as testurl from 'url-regex'
import * as jwt from 'jsonwebtoken'
import * as jose from 'node-jose'

import {
  exceptionHandler,
} from './utils'

import {
  Request,
  Response,
  NextFunction,
} from 'express'

import {
  AuthenticationAgent,
  AuthenticationParams,
  AuthorizationParams,
  Secret,
  TokenVerification,
  RoutePolicy,
  ParsedRoutePolicy,
} from './types'

import {
  authentication$API_GATEWAY, authentication$SERVER, authentication$ENUM,
  keys$CLAIMS, keys$ORGANIZATION_GROUP, keys$ORGANIZATION_ID, keys$ROLES, keys$USER_ID,
  tokenverify$PEM, tokenverify$JWK, tokenverify$PLAIN_TEXT, tokenverify$ENUM,
} from './constants'

interface RequestExtended extends Request {
  context?: any
}

class ExpressAuthorizer {
  authentication_agent: AuthenticationAgent
  use_authorization: boolean
  #token_verification?: TokenVerification
  token_secret?: Secret
  #identity_context_header_key?: string
  #identity_context_transformation_function?: Function
  #user_claims_root_key: string
  #user_id_key: string
  #user_roles_key: string
  #organization_group_key: string
  #organization_id_key: string
  #route_policies: ParsedRoutePolicy[]
  #decoded_token: any

  constructor (authentication_agent: AuthenticationAgent, use_authorization: boolean = true) {
    if (!authentication$ENUM.includes(authentication_agent)) {
      exceptionHandler(
        'INVALID_ENUM',
        'authentication_agent',
        authentication$ENUM,
      )
    }
    this.authentication_agent = authentication_agent
    this.use_authorization = use_authorization
    this.#user_claims_root_key = ''
    this.#user_id_key = ''
    this.#user_roles_key = ''
    this.#organization_group_key = ''
    this.#organization_id_key = ''
    this.#route_policies = []
  }

  private async initialize_remote_secret (uri: string, refresh_interval?: number) {
    this.token_secret = await this.fetch_secret(uri)
    const _this = this
    if (refresh_interval) setInterval(async function f() {
      _this.token_secret = await _this.fetch_secret(uri)
    }, refresh_interval * 60 * 1000)
  }

  private async fetch_secret(uri: string) {
    try {
      const { data } = await axios.get(uri)
      return data
    } catch (err) {
      console.error('fetch_secret', err)
      return
    }
  }

  private build_certificate(str: string) {
    return str
    .replace('-----BEGIN CERTIFICATE-----', '-----BEGIN-CERTIFICATE-----')
    .replace('-----END CERTIFICATE-----', '-----END-CERTIFICATE-----')
    .split(' ')
    .join('\n')
    .replace('-----END-CERTIFICATE-----', '-----END CERTIFICATE-----')
    .replace('-----BEGIN-CERTIFICATE-----', '-----BEGIN CERTIFICATE-----')
  }

  private authenticate_PLAIN_TEXT(token: string, secret: any, res: Response) {
    try {
      this.#decoded_token = jwt.verify(token, secret)
    } catch (err) {
      return res.sendStatus(401)
    }
  }

  private authenticate_PEM(token: string, secret: any, res: Response) {
    const decodedFull = jwt.decode(token, { complete: true })
    const kid = decodedFull?.header?.kid
    try {
      this.#decoded_token = jwt.verify(
        token,
        this.build_certificate(kid && typeof secret !== 'string'? secret[kid] : secret),
      )
    } catch (err) {
      console.info(err)
      return res.sendStatus(401)
    }
  }

  private async authenticate_JWK(token: string, secret: any, res: Response) {
    const decodedFull = jwt.decode(token, { complete: true })
    const kid = decodedFull?.header?.kid
    try {
      const keystore = await jose.JWK.asKeyStore(typeof secret.keys === 'object'
        ? { keys: secret.keys }
        : { keys: Array.isArray(secret) ? secret : [secret] })
      const rawKey = keystore.get(kid)
      const key = await jose.JWK.asKey(rawKey)
      this.#decoded_token = jwt.verify(token, key.toPEM(false))
    } catch (err) {
      console.info(err)
      return res.sendStatus(401)
    }
  }

  token_verification_params({
    method,
    secret,
    secret_refresh_interval,
  }: AuthenticationParams) {
    this.#token_verification = method
    const token_secret_uri = typeof secret === 'string' && testurl({ exact: true }).test(secret)
      ? secret
      : false
    this.token_secret = token_secret_uri
      ? undefined
      : secret
    if (this.authentication_agent === authentication$API_GATEWAY) throw exceptionHandler(
      'INVALID_METHOD',
      'tokenVerification',
      undefined,
      `when authentication_agent=${authentication$API_GATEWAY}`,
    )
    if (!tokenverify$ENUM.includes(method)) throw exceptionHandler(
      'INVALID_ENUM',
      'method',
      tokenverify$ENUM,
    )
    if (method === tokenverify$PLAIN_TEXT && typeof secret !== 'string') throw exceptionHandler(
      'INVALID_TYPE',
      'secret',
      undefined,
      `when method=${tokenverify$PLAIN_TEXT}`,
    )
    if (method === tokenverify$JWK && !token_secret_uri && typeof secret !== 'object') throw exceptionHandler(
      'INVALID_TYPE',
      'secret',
      undefined,
      `when method=${tokenverify$JWK}`,
    )
    if (token_secret_uri) this.initialize_remote_secret(token_secret_uri, secret_refresh_interval)
  }

  authorization_params({
    identity_context_header_key,
    identity_context_transformation_function,
    user_claims_root_key = keys$CLAIMS,
    user_id_key = keys$USER_ID,
    user_roles_key = keys$ROLES,
    organization_group_key = keys$ORGANIZATION_GROUP,
    organization_id_key = keys$ORGANIZATION_ID,
  }: AuthorizationParams) {
    if (this.authentication_agent === authentication$SERVER && (identity_context_header_key || identity_context_transformation_function)) {
      console.warn(exceptionHandler(
        'IGNORED_PROP',
        'identity_context_header_key | identity_context_transformation_function',
        undefined,
        `when authentication_agent=${authentication$SERVER}`
      ))
    }
    if (this.authentication_agent === authentication$API_GATEWAY && !identity_context_header_key) {
      console.warn(exceptionHandler(
        'DEFAULT_BEHAVIOR',
        'identity_context_header_key',
        undefined,
        `decoding the Bearer Token when "authentication_agent=${authentication$API_GATEWAY}"`
      ))
    }
    if (identity_context_transformation_function && !identity_context_header_key) {
      throw exceptionHandler(
        'REQUIRED_CONDITIONAL',
        'identity_context_header_key',
        undefined,
        'when "identity_context_transformation_function" is defined',
      )
    }
    this.#identity_context_header_key = identity_context_header_key
    this.#identity_context_transformation_function = identity_context_transformation_function
    this.#user_claims_root_key = user_claims_root_key
    this.#user_id_key = user_id_key
    this.#user_roles_key = user_roles_key
    this.#organization_group_key = organization_group_key
    this.#organization_id_key = organization_id_key
  }

  add_route_policy(policy: RoutePolicy) {
    const operations = policy.operations.reduce((acc: string[], oprt) => ([
      ...acc,
      ...oprt.methods.map((mthd: string) => `${mthd} ${oprt.path}`),
    ]), [])
    let roles = policy.authorized_roles.reduce((acc: string[], cur: any) => ([
      ...acc,
      ...typeof cur === 'string' // condition 1
        ? [cur]
        : typeof cur.roles === 'string' // condition 2
        ? [cur.organization_group === '*' && cur.roles === '*' ? '*' : `${cur.organization_group}:${cur.roles}`]
        : cur.roles.map((role: any) => `${cur.organization_group}:${role}`),
    ]), [])
    roles = [...new Set(roles)]
    this.#route_policies = [
      ...this.#route_policies,
      ...operations.reduce((acc, oprt): any => ([
        ...acc,
        ...roles.map((role): object => ({
          operation: oprt,
          role,
          restrict_organization_id: typeof policy.restrict_organization_id === 'undefined'
            ? true
            : policy.restrict_organization_id,
          organization_id_alt_key: policy.organization_id_alt_key,
        })),
      ]), []),
    ]
  }

  async authenticate(req: Request, res: Response, next: NextFunction) {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '') || ''
      const secret = this.token_secret || ''
      const secretJWK = this.#token_verification === tokenverify$JWK
      const secretPEM = this.#token_verification === tokenverify$PEM
      const secretPLAIN_TEXT = this.#token_verification === tokenverify$PLAIN_TEXT
      const authSERVER = this.authentication_agent === authentication$SERVER
      if (authSERVER && secretJWK) await this.authenticate_JWK(token, secret, res)
      if (authSERVER && secretPEM) await this.authenticate_PEM(token, secret, res)
      if (authSERVER && secretPLAIN_TEXT) await this.authenticate_PLAIN_TEXT(token, secret, res)
      if (this.use_authorization) return this.authorize(req, res, next)
      next()
    } catch (err) {
      console.error(err)
      return res.sendStatus(401)
    }
  }

  private extractReqValue(req: Request, key: string | undefined, alt: string | undefined) {
    return !key
      ? alt
      : req.params && req.params[key]
      ? req.params[key]
      : req.query && req.query[key]
      ? req.query[key]
      : req.body && req.body[key]
      ? req.body[key]
      : alt
  }

  authorize(req: RequestExtended, res: Response, next: NextFunction) {
    try {
      const identityContextKey = this.#identity_context_header_key
      const rawContext = identityContextKey ? req.headers[identityContextKey] : undefined
      const parseContext = this.#identity_context_transformation_function
      const decodedToken = this.authentication_agent === authentication$SERVER
        ? this.#decoded_token
        : !rawContext
        ? jwt.decode((req.headers.authorization || '').replace('Bearer ', ''))
        : parseContext
        ? parseContext(rawContext)
        : rawContext
      if (!decodedToken) return res.sendStatus(403)
      req.context = decodedToken

      const userId = decodedToken[this.#user_id_key]
      const customClaims = decodedToken[this.#user_claims_root_key]
      const roles = customClaims.reduce((acc: string[], claim: any) => ([
        ...acc,
        ...[
          ...claim[this.#user_roles_key].map((role: string) => `${claim[this.#organization_group_key]}:${role}:${claim[this.#organization_id_key]}`),
          ...claim[this.#user_roles_key].map((role: string) => `${claim[this.#organization_group_key]}:${role}:*`),
          `${claim[this.#organization_group_key]}:*:${claim[this.#organization_id_key]}`,
          `${claim[this.#organization_group_key]}:*:*`,
        ],
      ]), [])

      const reqOrganizationId = this.extractReqValue(req, this.#organization_id_key, '*')
      const reqUserId = this.extractReqValue(req, this.#user_id_key, undefined)
      const policies = this.#route_policies
        .filter(policy => policy.operation === `${req.method.toUpperCase()} ${req.path}`)

      const isOpenToAnyone = !policies.length || policies.find(policy => policy.role === '*')
      if (isOpenToAnyone) return next()

      const policyIncludesSelf = policies.find(policy => policy.role === 'self')
      if (policyIncludesSelf && reqUserId === 'me') return next()
      const authorizedSelf = policyIncludesSelf && reqUserId === userId

      const authorizedRoles = policies.map(policy => policy.restrict_organization_id
        ? `${policy.role}:${this.extractReqValue(req, policy.organization_id_alt_key, undefined) || reqOrganizationId}`
        : `${policy.role}:*`)
      const intersection = authorizedRoles.find(item => roles.includes(item))

      if (!authorizedSelf && !intersection) return res.sendStatus(403)
      next()
    } catch (err) {
      console.error(err)
      return res.sendStatus(401)
    }
  }
}

export default ExpressAuthorizer
