; Query for finding Flask route decorators and endpoint patterns
; Used to extract HTTP endpoints and their routing information

; Pattern 1: @app.route('/path', methods=['GET', 'POST'])
; Pattern 2: @bp.route('/path')
(decorator
  (call
    function: (attribute
      object: (identifier) @app_or_bp_var
      attribute: (identifier) @decorator_method
    )
    arguments: (argument_list) @route_args
  )
) @route_decorator

; Pattern 3: @app.get('/users')
; Pattern 4: @app.post('/users')
; Pattern 5: @bp.delete('/users')
; New-style HTTP method decorators (Flask 2.0+)
(decorator
  (call
    function: (attribute
      object: (identifier) @app_or_bp_var
      attribute: (identifier) @http_method
    )
    arguments: (argument_list
      [(string) @route_path
       (keyword_argument)]
    ) @method_args
  )
) @http_method_decorator

; Pattern 6: @app.errorhandler(404)
; Pattern 7: @app.errorhandler(Exception)
(decorator
  (call
    function: (attribute
      object: (identifier) @app_var
      attribute: (identifier) @errorhandler_method
    )
    arguments: (argument_list
      [
        (integer) @error_code
        (identifier) @error_class
      ]
    )
  )
) @errorhandler_decorator
