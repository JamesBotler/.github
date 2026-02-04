# Policy and Runner Pipeline

## Intent

Show the generic policy gate and runner execution for any tool call.

## Pseudocode

```text
def execute_tool_call(proposal, principal, contract):
  # 1) Policy evaluation
  decision = policy.evaluate(proposal, principal, contract)
  if decision == "DENY":
    audit.log(decision, proposal, {"error": "denied"})
    return error("denied")

  if decision == "APPROVAL_REQUIRED":
    ui.request_approval(decision)
    if not ui.approved(decision):
      audit.log(decision, proposal, {"error": "not approved"})
      return error("not approved")

  # 2) Acquire short-lived handle
  handle = broker.acquire_handle(decision.id, proposal.id)

  # 3) Execute in isolated runner
  result = runner.execute(proposal, handle)

  # 4) Sanitize output and store artifacts if needed
  result = output_sanitizer(result)
  if is_large(result):
    result = artifact_store.write(result)

  # 5) Audit logging
  audit.log(decision, proposal, result)
  return result
```

## Notes

- The LLM never receives secrets or handles.
- Output is filtered before returning to the model.
- Artifacts are used for large outputs.
