# Scheduled Digest Job (Reusable Contract)

## Intent

Nightly email digest and Slack summary under a reusable contract.

## Pseudocode

```text
contract = ReusableContract(
  tools = ["gmail.search", "gmail.getMessage", "slack.post"],
  bounds = {
    "gmail.search": {"query": "from:alerts@corp.com newer_than:1d label:ops", "max_results": 50},
    "gmail.getMessage": {"fields": ["subject", "from", "date", "snippet"], "max_messages": 10},
    "slack.post": {"channel": "#ops-alerts", "max_chars": 4000}
  },
  budgets = {"tool_calls": 20, "max_runtime_s": 60, "max_messages": 1}
)

scheduler.on_tick("02:00", timezone="local"):
  principal = "job:nightly_ops_digest"
  budget.reset(principal)

  search_call = ToolCall("gmail.search", {"query": contract.bounds.gmail.search.query})
  decision = policy.evaluate(search_call, principal, contract)
  if decision != "ALLOW":
    return pause_job(decision)

  handle = broker.acquire_handle(decision.id, search_call.id)
  results = runner.execute(search_call, handle)
  results = output_sanitizer(results)
  audit.log(decision, search_call, results)

  msgs = []
  for id in results.message_ids[:10]:
    get_call = ToolCall("gmail.getMessage", {"message_id": id, "fields": contract.bounds.gmail.getMessage.fields})
    decision = policy.evaluate(get_call, principal, contract)
    if decision != "ALLOW":
      return pause_job(decision)
    handle = broker.acquire_handle(decision.id, get_call.id)
    msg = runner.execute(get_call, handle)
    msgs.append(output_sanitizer(msg))
    audit.log(decision, get_call, msg)

  summary = llm.summarize(msgs)
  post_call = ToolCall("slack.post", {"channel": "#ops-alerts", "text": summary})
  decision = policy.evaluate(post_call, principal, contract)
  if decision != "ALLOW":
    return pause_job(decision)

  handle = broker.acquire_handle(decision.id, post_call.id)
  runner.execute(post_call, handle)
  audit.log(decision, post_call, {"ok": true})
```

## Notes

- Jobs run under a job principal, not a user session.
- Any deviation pauses the job for re-approval.
- Idempotency keys and outbox prevent duplicate side effects.
