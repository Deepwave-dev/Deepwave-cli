; Find all class definitions (including decorated ones)
; Priority: decorated_definition first (so we can check decorators)
(decorated_definition
  definition: (class_definition
    name: (identifier) @class_name
    superclasses: (argument_list)? @superclasses
  ) @class
)

; Also find non-decorated class definitions
(class_definition
  name: (identifier) @class_name
  superclasses: (argument_list)? @superclasses
) @class

