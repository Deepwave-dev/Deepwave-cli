; Query for finding FastAPI Depends() patterns in function parameters and router configurations
; Used to extract dependency injection relationships

; Pattern 1: Function parameter with Depends() - user: User = Depends(get_current_user)
(parameters
  (typed_default_parameter
    (identifier) @param_name
    type: (_)? @param_type
    value: (call
      function: (identifier) @depends_func
      arguments: (argument_list) @depends_args
    ) @depends_call
  ) @depends_param
)

; Pattern 2: Untyped parameter with Depends() - db = Depends(get_db)
(parameters
  (default_parameter
    (identifier) @param_name
    value: (call
      function: (identifier) @depends_func
      arguments: (argument_list) @depends_args
    ) @depends_call
  ) @depends_param_untyped
)

; Pattern 3: Attribute-based Depends() in parameters - user: User = Depends(auth.get_user)
(parameters
  (typed_default_parameter
    (identifier) @param_name
    type: (_)? @param_type
    value: (call
      function: (attribute) @depends_attr
      arguments: (argument_list) @depends_args
    ) @depends_call_attr
  ) @depends_param_attr
)

; Pattern 4: Router-level dependencies - APIRouter(dependencies=[Depends(verify_token)])
(call
  function: (identifier) @router_func
  arguments: (argument_list
    (keyword_argument
      name: (identifier) @kwarg_name
      value: (list
        (call
          function: (identifier) @depends_func
          arguments: (argument_list) @depends_args
        ) @depends_call
      ) @depends_list
    ) @router_dependencies
  ) @router_args
)

