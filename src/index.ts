import axios from 'axios'
import * as testurl from 'url-regex'
import * as jwt from 'jsonwebtoken'
import * as jose from 'node-jose'

import {
  match,
  MatchResult,
} from 'path-to-regexp'

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

import {
  exceptionHandler,
} from './utils'

interface RequestExtended extends Request {
  context?: any
}

class ExpressAuthorizer {
  authentication_agent: AuthenticationAgent
  token_verification?: TokenVerification
  token_secret?: Secret
  identity_context_header_key?: string
  identity_context_transformation_function?: Function
  user_claims_root_key: string
  user_id_key: string
  user_roles_key: string
  organization_group_key: string
  private organization_id_key: string
  route_policies: ParsedRoutePolicy[]
  decoded_token: any

  constructor (authentication_agent: AuthenticationAgent) {
    if (!authentication$ENUM.includes(authentication_agent)) {
      exceptionHandler(
        'INVALID_ENUM',
        'authentication_agent',
        authentication$ENUM,
      )
    }
    this.authentication_agent = authentication_agent
    this.user_claims_root_key = ''
    this.user_id_key = ''
    this.user_roles_key = ''
    this.organization_group_key = ''
    this.organization_id_key = ''
    this.route_policies = []
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

  private extract_value(
    req: Request,
    params: any,
    key: string | undefined,
    altKey: string | undefined,
    alt: string | undefined
  ) {
    return altKey && params
      ? params[altKey]
      : altKey && req.query
      ? req.query[altKey]
      : altKey && req.body
      ? req.body[altKey]
      : key && params
      ? params[key]
      : key && req.query
      ? req.query[key]
      : key && req.body
      ? req.body[key]
      : alt
  }

  private authenticate_PLAIN_TEXT(token: string, secret: any) {
    try {
      this.decoded_token = jwt.verify(token, secret)
      return true
    } catch (err) {
      return false
    }
  }

  private authenticate_PEM(token: string, secret: any) {
    const decodedFull = jwt.decode(token, { complete: true })
    const kid = decodedFull?.header?.kid
    try {
      this.decoded_token = jwt.verify(
        token,
        this.build_certificate(kid && typeof secret !== 'string'? secret[kid] : secret),
      )
      return true
    } catch (err) {
      console.info(err)
      return false
    }
  }

  private async authenticate_JWK(token: string, secret: any) {
    const decodedFull = jwt.decode(token, { complete: true })
    const kid = decodedFull?.header?.kid
    try {
      const keystore = await jose.JWK.asKeyStore(typeof secret.keys === 'object'
        ? { keys: secret.keys }
        : { keys: Array.isArray(secret) ? secret : [secret] })
      const rawKey = keystore.get(kid)
      const key = await jose.JWK.asKey(rawKey)
      this.decoded_token = jwt.verify(token, key.toPEM(false))
      return true
    } catch (err) {
      console.info(err)
      return false
    }
  }

  token_verification_params({
    method,
    secret,
    secret_refresh_interval,
  }: AuthenticationParams) {
    this.token_verification = method
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
    this.identity_context_header_key = identity_context_header_key
    this.identity_context_transformation_function = identity_context_transformation_function
    this.user_claims_root_key = user_claims_root_key
    this.user_id_key = user_id_key
    this.user_roles_key = user_roles_key
    this.organization_group_key = organization_group_key
    this.organization_id_key = organization_id_key
  }

  add_route_policy(policy: RoutePolicy) {
    const operations = policy.operations.reduce((acc: string[], oprt) => ([
      ...acc,
      ...oprt.methods.map((mthd: string) => `/${mthd.toLowerCase()}/${oprt.path}`),
    ]), [])

    let roles = typeof policy.authorized_roles === 'string'
      ? [policy.authorized_roles]
      : policy.authorized_roles.reduce((acc: string[], cur: any) => ([
        ...acc,
        ...typeof cur.roles === 'string'
          ? [cur.organization_group === '*' && cur.roles === '*' ? '*' : `${cur.organization_group}:${cur.roles}`]
          : cur.roles.map((role: any) => `${cur.organization_group}:${role}`),
      ]), [])
    roles = [...new Set(roles)]

    this.route_policies = [
      ...this.route_policies,
      ...operations.reduce((acc, oprt): any => ([
        ...acc,
        ...roles.map((role): ParsedRoutePolicy => ({
          operation: oprt,
          role,
          organization_restricted: policy.organization_restricted === undefined
            ? true
            : policy.organization_restricted,
          organization_id_alt_key: policy.organization_id_alt_key,
          user_id_alt_key: policy.user_id_alt_key,
        })),
      ]), []),
    ]
  }

  authenticate = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = req.headers.authorization?.replace('Bearer ', '') || ''
      const secret = this.token_secret || ''
      const secretJWK = this.token_verification === tokenverify$JWK
      const secretPEM = this.token_verification === tokenverify$PEM
      const secretPLAIN_TEXT = this.token_verification === tokenverify$PLAIN_TEXT
      const authSERVER = this.authentication_agent === authentication$SERVER
      let answer
      if (authSERVER && secretJWK) answer = await this.authenticate_JWK(token, secret)
      if (authSERVER && secretPEM) answer = await this.authenticate_PEM(token, secret)
      if (authSERVER && secretPLAIN_TEXT) answer = await this.authenticate_PLAIN_TEXT(token, secret)
      if (!answer) throw 'Unauthorized'
      next()
    } catch (err) {
      console.error(err)
      return res.sendStatus(401)
    }
  }

  authorize = (req: RequestExtended, res: Response, next: NextFunction) => {
    const {
      method,
      path,
      headers,
    } = req
    const {
      route_policies: routepolicies,
      identity_context_header_key: idcontextkey,
      identity_context_transformation_function: contextfunction,
      authentication_agent: authagent,
      decoded_token: decodedtoken,
      extract_value: extractfunction,
      user_claims_root_key: claimskey,
      user_id_key: useridkey,
      user_roles_key: roleskey,
      organization_group_key: orggroupkey,
      organization_id_key: orgidkey,
    } = this
    try {
      const policies = routepolicies.reduce((acc: (ParsedRoutePolicy & MatchResult)[], cur: ParsedRoutePolicy) => {
        const matcher = match(cur.operation, { decode: decodeURIComponent })
        const _match = matcher(`/${method.toLowerCase()}/${path}`)
        return _match ? [...acc, { ...cur, ..._match }] : acc
      }, [])
      if (!policies.length) return next()

      const isopen = policies.find(policy => (policy && policy.role === '*'))
      if (isopen) return next()

      const rawcontext = idcontextkey ? headers[idcontextkey] : undefined
      const token = authagent === authentication$SERVER
        ? decodedtoken
        : !rawcontext
        ? jwt.decode((headers.authorization || '').replace('Bearer ', ''))
        : contextfunction
        ? contextfunction(rawcontext)
        : rawcontext
      if (!token) throw 'Forbidden'
      req.context = token

      const userid = token[useridkey]
      const selfpolicy = policies.find(policy => policy.role === 'self')
      const { params: selfparams, user_id_alt_key: useridaltkey } = selfpolicy || {}
      const useridreq = extractfunction(req, selfparams, useridkey, useridaltkey, undefined)
      if (selfpolicy && useridreq === 'me') return next()
      let authorized: any = (selfpolicy && useridreq === userid)
        || (selfpolicy && Array.isArray(useridreq) && useridreq.includes(userid))
      if (authorized) return next()

      const rolepolicies = policies.filter(policy => !['*', 'self'].includes(policy.role))
      if (!rolepolicies.length) throw 'Forbidden'

      const orgidreq = extractfunction(req, undefined, orgidkey, undefined, '*')
      const authdroles = rolepolicies.map(policy => policy.organization_restricted
        ? `${policy.role}:${extractfunction(req, policy.params, orgidkey, policy.organization_id_alt_key, undefined) || orgidreq}`
        : `${policy.role}:*`)
      const customclaims = token[claimskey]
      const userroles = customclaims.reduce((acc: string[], claim: any) => ([
        ...acc,
        ...[
          ...claim[roleskey].map((role: string) => `${claim[orggroupkey]}:${role}:${claim[orgidkey]}`),
          ...claim[roleskey].map((role: string) => `${claim[orggroupkey]}:${role}:*`),
          `${claim[orggroupkey]}:*:${claim[orgidkey]}`,
          `${claim[orggroupkey]}:*:*`,
        ],
      ]), [])
      authorized = authdroles.find(item => userroles.includes(item))
      if (authorized) return next()
      throw 'Forbidden'
    } catch (err) {
      console.error(err)
      return res.sendStatus(403)
    }
  }
}

export default ExpressAuthorizer
