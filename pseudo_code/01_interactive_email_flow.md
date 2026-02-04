# Interactive Email Flow (One-shot Contract)

## Intent

Read an email, analyze it, and draft or send a reply.

## Pseudocode

```text
contract = OneShotContract(
  tools = ["gmail.getMessage", "gmail.createDraft", "gmail.send"],
  bounds = {
    "gmail.getMessage": {"fields": ["subject", "from", "date", "snippet"]},
    "gmail.send": {"allowed_recipients": ["example@corp.com"], "max_chars": 4000}
  },
  budgets = {"tool_calls": 5, "max_runtime_s": 60}
)

on_user_request(request):
  # Step 1: propose a tool call
  proposal = ToolCall("gmail.getMessage", {"message_id": request.message_id})

  decision = policy.evaluate(proposal, principal="session:123", contract)
  if decision == "APPROVAL_REQUIRED":
    ui.request_approval(decision)
    if not ui.approved(decision):
      return "denied"

  if decision != "ALLOW":
    return "denied"

  handle = broker.acquire_handle(decision.id, proposal.id)
  msg = runner.execute(proposal, handle)
  msg = output_sanitizer(msg)
  audit.log(decision, proposal, msg)

  # Step 2: LLM analyzes content
  reply = llm.analyze_and_draft(msg)

  # Step 3: create draft or send
  draft_call = ToolCall("gmail.createDraft", {"to": msg.from, "body": reply})
  decision = policy.evaluate(draft_call, principal="session:123", contract)
  if decision == "APPROVAL_REQUIRED":
    ui.request_approval(decision)
    if not ui.approved(decision):
      return "denied"

  handle = broker.acquire_handle(decision.id, draft_call.id)
  draft = runner.execute(draft_call, handle)
  audit.log(decision, draft_call, draft)

  return draft.id
```

## Notes

- The LLM never receives secrets or tokens.
- High-risk actions require Control UI approval.
- Output is sanitized before the LLM sees it.
