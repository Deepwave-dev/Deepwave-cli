; Query for finding Flask blueprint registration patterns
; Used to extract app.register_blueprint() relationships

; Pattern 1: app.register_blueprint(users_bp)
; Pattern 2: app.register_blueprint(users_bp, url_prefix='/api/users')
; Pattern 3: app.register_blueprint(users_bp, subdomain='admin')
(call
  function: (attribute
    object: (identifier) @app_var
    attribute: (identifier) @register_method
  )
  arguments: (argument_list
    [
      (identifier) @bp_arg
      (attribute) @bp_attr
      (call) @bp_call
      (keyword_argument
        name: (identifier) @kwarg_name
        value: (_) @kwarg_value
      )
    ]*
  ) @register_args
) @register_blueprint_call

; Pattern 4: Blueprint instantiation - bp = Blueprint('name', __name__)
(assignment
  left: (identifier) @bp_var
  right: (call
    function: (identifier) @blueprint_class
    arguments: (argument_list
      (string) @bp_name
      (_)*
    )
  )
) @blueprint_assignment
