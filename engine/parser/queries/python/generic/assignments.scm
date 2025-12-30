; Find all assignment statements
; This is a generic query that captures ALL assignments in Python code
; Pattern: variable = expression

; Pattern 1: Simple assignment (var = value)
(assignment
  left: (identifier) @var_name
  right: (_) @value
) @assignment

; Pattern 2: Assignment with call on right side (var = func())
; This is the most common pattern for app = FastAPI(), router = APIRouter(), etc.
(assignment
  left: (identifier) @var_name
  right: (call
    function: (_) @func
  ) @call_value
) @assignment_call

; Pattern 3: Multiple assignment targets (a = b = value)
(assignment
  left: (pattern_list) @targets
  right: (_) @value
) @multi_assignment

