import { Union, Literal, Static,  } from 'runtypes'
import { httpmethods$DELETE, httpmethods$GET, httpmethods$PATCH, httpmethods$POST, httpmethods$PUT } from '../constants'

const HTTPMethodEnum = Union(
  Literal(httpmethods$DELETE),
  Literal(httpmethods$GET),
  Literal(httpmethods$PATCH),
  Literal(httpmethods$POST),
  Literal(httpmethods$PUT),
)
type HTTPMethod = Static<typeof HTTPMethodEnum>

type Operation = {
  path: string
  methods: HTTPMethod[]
}

type AuthorizedRole = {
  organization_group: '*' | string
  roles: '*' | string[]
}

export type RoutePolicy = {
  operations: Operation[]
  authorized_roles: ('self' | '*' | AuthorizedRole)[]
  restrict_organization_id?: boolean
  organization_id_alt_key?: string
}

export type ParsedRoutePolicy = {
  operation: string
  role: string
  restrict_organization_id: boolean
  organization_id_alt_key?: string
}
