; Query for finding Flask hook decorators
; Used to identify before_request, after_request, and other lifecycle hooks

; Pattern 1: @app.before_request
; Pattern 2: @app.after_request
; Pattern 3: @app.teardown_request
; Pattern 4: @app.before_first_request (deprecated but still used)
; Pattern 5: @app.teardown_appcontext
; Pattern 6: @app.context_processor
(decorator
  (attribute
    object: (identifier) @app_or_bp_var
    attribute: (identifier) @hook_type
  )
) @hook_decorator

; Pattern 7: @app.before_request with call (rare, but possible)
(decorator
  (call
    function: (attribute
      object: (identifier) @app_or_bp_var
      attribute: (identifier) @hook_type_call
    )
    arguments: (argument_list)
  )
) @hook_decorator_call

; Pattern 8: @app.template_filter('filter_name')
; Pattern 9: @app.template_test('test_name')
(decorator
  (call
    function: (attribute
      object: (identifier) @app_var
      attribute: (identifier) @template_hook
    )
    arguments: (argument_list
      (string) @filter_name
    )
  )
) @template_decorator
