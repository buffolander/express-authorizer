export type AuthorizationParams = {
  identity_context_header_key?: string
  identity_context_transformation_function?: Function
  user_claims_root_key?: string
  user_id_key?: string
  user_roles_key?: string
  organization_group_key?: string
  organization_id_key?: string
}
