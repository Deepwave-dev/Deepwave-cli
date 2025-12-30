; Find all decorators
; This is a generic query that captures ALL decorators in Python code
; Decorators can be on functions, classes, or methods

; Pattern 1: Decorated function with simple decorator (@decorator)
(decorated_definition
  (decorator
    (identifier) @decorator_name
  ) @decorator
  definition: (function_definition
    name: (identifier) @function_name
  ) @function
) @decorated_function

; Pattern 2: Decorated function with decorator call (@decorator())
(decorated_definition
  (decorator
    (call
      function: (identifier) @decorator_func
    ) @decorator_call
  ) @decorator
  definition: (function_definition
    name: (identifier) @function_name
  ) @function
) @decorated_function_call

; Pattern 3: Decorated function with attribute decorator (@router.get)
(decorated_definition
  (decorator
    (attribute
      object: (identifier) @decorator_object
      attribute: (identifier) @decorator_method
    ) @decorator_attr
  ) @decorator
  definition: (function_definition
    name: (identifier) @function_name
  ) @function
) @decorated_function_attr

; Pattern 4: Decorated function with attribute decorator call (@router.get("/path"))
(decorated_definition
  (decorator
    (call
      function: (attribute
        object: (identifier) @decorator_object
        attribute: (identifier) @decorator_method
      ) @decorator_attr
      arguments: (argument_list) @decorator_args
    ) @decorator_call
  ) @decorator
  definition: (function_definition
    name: (identifier) @function_name
  ) @function
) @decorated_function_attr_call

; Pattern 5: Decorated class
(decorated_definition
  (decorator) @decorator
  definition: (class_definition
    name: (identifier) @class_name
  ) @class
) @decorated_class

