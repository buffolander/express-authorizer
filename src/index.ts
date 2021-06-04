import axios from 'axios'
import isURL from 'validator/lib/isURL'
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
  authentication$API_GATEWAY,
  authentication$SERVER,
  authentication$ENUM,
  keys$CLAIMS,
  keys$ORGANIZATION_GROUP,
  keys$ORGANIZATION_ID,
  keys$ROLES,
  keys$USER_ID,
  tokenverify$PEM,
  tokenverify$JWK,
  tokenverify$PLAIN_TEXT,
  tokenverify$ENUM,
} from './constants'

import {
  exceptionHandler,
} from './utils'

interface RequestExtended extends Request {
  context?: any
}

class ExpressAuthorizer {
  private authagent: AuthenticationAgent
  private contextkey?: string
  private contextfunction?: Function
  private keyclaims: string
  private keyuserid: string
  private keyroles: string
  private keygroup: string
  private keyorgid: string
  private policies: ParsedRoutePolicy[]
  private tokensecret?: Secret
  private tokencheck?: TokenVerification
  private audience?: string
  private issuer?: string
  private tokenres: any

  constructor (authentication_agent: AuthenticationAgent) {
    if (!authentication$ENUM.includes(authentication_agent))
      throw exceptionHandler('INVALID_ENUM', 'authentication_agent', authentication$ENUM)
    this.authagent = authentication_agent
    this.keyclaims = ''
    this.keyuserid = ''
    this.keyroles = ''
    this.keygroup = ''
    this.keyorgid = ''
    this.policies = []
  }

  private async initialize_remote_secret (uri: string, refresh_interval?: number) {
    this.tokensecret = await this.fetch_secret(uri)
    const _this = this
    const refreshms = refresh_interval ? refresh_interval * 60 * 1000 : undefined
    if (refreshms) setInterval(async function f() { _this.tokensecret = await _this.fetch_secret(uri) }, refreshms)
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
    return altKey && req.query && req.query[altKey]
      ? req.query[altKey]
      : altKey && req.body && req.body[altKey]
      ? req.body[altKey]
      : altKey && params && params[altKey]
      ? params[altKey]
      : key && req.query && req.query[key]
      ? req.query[key]
      : key && req.body && req.body[key]
      ? req.body[key]
      : key && params && params[key]
      ? params[key]
      : alt
  }

  private authenticate_PLAIN_TEXT(token: string, secret: any) {
    try {
      this.tokenres = jwt.verify(token, secret, {
        audience: this.audience,
        issuer: this.issuer,
      })
      return this.tokenres
    } catch (err) {
      console.error(this.authenticate_PLAIN_TEXT.name, err)
      return undefined
    }
  }

  private authenticate_PEM(token: string, secret: any) {
    try {
      const tokenfull = jwt.decode(token, { complete: true })
      const kid = tokenfull?.header?.kid
      const cert = this.build_certificate(kid && typeof secret !== 'string'? secret[kid] : secret)
      this.tokenres = jwt.verify(token, cert, {
        audience: this.audience,
        issuer: this.issuer,
      })
      return this.tokenres
    } catch (err) {
      console.error(this.authenticate_PEM.name, err)
      return undefined
    }
  }

  private async authenticate_JWK(token: string, secret: any) {
    const tokenfull = jwt.decode(token, { complete: true })
    const kid = tokenfull?.header?.kid
    try {
      const keystore = await jose.JWK.asKeyStore(typeof secret.keys === 'object'
        ? { keys: secret.keys }
        : { keys: Array.isArray(secret) ? secret : [secret] })
      const rawkey = keystore.get(kid)
      const key = await jose.JWK.asKey(rawkey)
      this.tokenres = jwt.verify(token, key.toPEM(false), {
        audience: this.audience,
        issuer: this.issuer,
      })
      return this.tokenres
    } catch (err) {
      console.error(this.authenticate_JWK.name, err)
      return undefined
    }
  }

  set_authentication_params = ({
    secret,
    secret_type,
    secret_refresh_interval,
    audience,
    issuer,
  }: AuthenticationParams) => {
    this.tokencheck = secret_type
    this.audience = audience
    this.issuer = issuer
    const url = typeof secret === 'string' && isURL(secret, { protocols: ['https'], require_protocol: true }) ? secret : undefined
    this.tokensecret = url ? undefined : secret
    if (this.authagent === authentication$API_GATEWAY)
      throw exceptionHandler('INVALID_METHOD', 'tokenVerification', undefined, `when authentication_agent=${authentication$API_GATEWAY}`)
    if (!tokenverify$ENUM.includes(secret_type))
      throw exceptionHandler('INVALID_ENUM', 'secret_type', tokenverify$ENUM)
    if (secret_type === tokenverify$PLAIN_TEXT && typeof secret !== 'string')
      throw exceptionHandler('INVALID_TYPE', 'secret', undefined, `when secret_type=${tokenverify$PLAIN_TEXT}`)
    if (secret_type === tokenverify$JWK && !url && typeof secret !== 'object')
      throw exceptionHandler('INVALID_TYPE', 'secret', undefined, `when secret_type=${tokenverify$JWK}`)
    if (url) this.initialize_remote_secret(url, secret_refresh_interval)
  }

  set_authorization_params = ({
    identity_context_header_key,
    identity_context_transformation_function,
    user_claims_root_key = keys$CLAIMS,
    user_id_key = keys$USER_ID,
    user_roles_key = keys$ROLES,
    organization_group_key = keys$ORGANIZATION_GROUP,
    organization_id_key = keys$ORGANIZATION_ID,
  }: AuthorizationParams) => {
    let checker: any = this.authagent === authentication$SERVER && (identity_context_header_key || identity_context_transformation_function)
    if (checker)
      console.warn(exceptionHandler(
        'IGNORED_PROP',
        'identity_context_header_key | identity_context_transformation_function',
        undefined,
        `when authentication_agent=${authentication$SERVER}`))
    checker = this.authagent === authentication$API_GATEWAY && !identity_context_header_key
    if (checker)
      console.warn(exceptionHandler(
        'DEFAULT_BEHAVIOR',
        'identity_context_header_key',
        undefined,
        `decoding the Bearer Token when "authentication_agent=${authentication$API_GATEWAY}"`))
    checker = identity_context_transformation_function && !identity_context_header_key
    if (checker)
      throw exceptionHandler(
        'REQUIRED_CONDITIONAL',
        'identity_context_header_key',
        undefined,
        'when "identity_context_transformation_function" is defined')
    this.contextkey = identity_context_header_key
    this.contextfunction = identity_context_transformation_function
    this.keyclaims = user_claims_root_key
    this.keyuserid = user_id_key
    this.keyroles = user_roles_key
    this.keygroup = organization_group_key
    this.keyorgid = organization_id_key
  }

  /**
   * @function add_policy Adds an authorization policy to the authorizer,
   * pairing service operations with authorized roles
   * @param policy
   */
  add_policy = (policy: RoutePolicy) => {
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

    this.policies = [
      ...this.policies,
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
      const secret = this.tokensecret || ''
      const secretJWK = this.tokencheck === tokenverify$JWK
      const secretPEM = this.tokencheck === tokenverify$PEM
      const secretPLAIN_TEXT = this.tokencheck === tokenverify$PLAIN_TEXT
      const authSERVER = this.authagent === authentication$SERVER
      let answer
      if (authSERVER && secretJWK) answer = await this.authenticate_JWK(token, secret)
      if (authSERVER && secretPEM) answer = await this.authenticate_PEM(token, secret)
      if (authSERVER && secretPLAIN_TEXT) answer = await this.authenticate_PLAIN_TEXT(token, secret)
      if (!answer) throw 'Unauthorized'
      req.headers.context = answer
      next()
    } catch (err) {
      console.error(this.authenticate.name, err)
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
      authagent,
      policies: routepolicies,
      contextkey,
      contextfunction,
      tokenres,
      keyclaims,
      keyuserid,
      keyroles,
      keygroup,
      keyorgid,
      extract_value: extractfunction,
    } = this
    try {
      const rawcontext = contextkey
        ? headers[contextkey.toLowerCase()]
        : undefined
      const context = authagent === authentication$SERVER
        ? tokenres
        : !rawcontext
        ? jwt.decode((headers.authorization || '').replace('Bearer ', ''))
        : contextfunction
        ? contextfunction(rawcontext)
        : rawcontext
      if (!context || !context.user_id) return next()
      req.headers.context = context

      const policies = routepolicies.reduce((acc: (ParsedRoutePolicy & MatchResult)[], cur: ParsedRoutePolicy) => {
        const matcher = match(cur.operation, { decode: decodeURIComponent })
        const _match = matcher(`/${method.toLowerCase()}/${path}`)
        return _match ? [...acc, { ...cur, ..._match }] : acc
      }, [])
      if (!policies.length) return next()

      const isopen = policies.find(policy => (policy && policy.role === '*'))
      if (isopen) return next()

      const userid = context[keyuserid]
      const selfpolicy = policies.find(policy => policy.role === 'self')
      const { params: selfparams, user_id_alt_key: useridaltkey } = selfpolicy || {}
      const useridreq = extractfunction(req, selfparams, keyuserid, useridaltkey, undefined)
      if (selfpolicy && useridreq === 'me') return next()
      let authorized: any = (selfpolicy && useridreq === userid)
        || (selfpolicy && Array.isArray(useridreq) && useridreq.includes(userid))
      if (authorized) return next()

      const rolepolicies = policies.filter(policy => !['*', 'self'].includes(policy.role))
      if (!rolepolicies.length) throw 'Forbidden'

      const orgidreq = extractfunction(req, undefined, keyorgid, undefined, undefined)
      const authdroles = rolepolicies.map(policy => policy.organization_restricted
        ? `${policy.role}:${extractfunction(req, policy.params, keyorgid, policy.organization_id_alt_key, undefined) || orgidreq}`
        : `${policy.role}:*`)
      let customclaims = context[keyclaims]
      customclaims = Array.isArray(customclaims) ? customclaims : [customclaims]
      const userroles = customclaims.reduce((acc: string[], claim: any) => ([
        ...acc,
        ...[
          ...claim[keyroles].map((role: string) => `${claim[keygroup]}:${role}:${claim[keyorgid]}`),
          ...claim[keyroles].map((role: string) => `${claim[keygroup]}:${role}:*`),
          `${claim[keygroup]}:*:${claim[keyorgid]}`,
          `${claim[keygroup]}:*:*`,
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
