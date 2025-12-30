; Query for finding function calls
; Used by CallGraphBuilderTreeSitter to extract function call relationships

; Pattern 1: Direct function call: foo()
(call
  function: (identifier) @function_name
) @call

; Pattern 2: Attribute-based call: obj.foo() or module.foo()
(call
  function: (attribute
    object: (identifier) @object_name
    attribute: (identifier) @method_name
  )
) @attribute_call

; Pattern 3: Nested attribute call: obj.sub.foo()
(call
  function: (attribute
    object: (attribute
      object: (identifier) @object_name
      attribute: (identifier) @sub_attr
    )
    attribute: (identifier) @method_name
  )
) @nested_attribute_call


