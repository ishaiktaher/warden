# Warden demo scenarios

Both scenarios use the same untrusted booking amount (₹6,000) and stated user
limit (₹5,000).

## Live presentation

Start the proxy and mock page together:

```bash
python -m demo.launch
```

The launcher prints the exact `/confirm-booking` Hermes prompt.

## Scenario 1: stated but unenforced

This demo-only soft-mode run creates a real Dodo **test-mode** ₹6,000 charge:

```bash
python -m demo.scenario_soft --confirm-test-charge
```

## Scenario 2: enforced outside the model

Hard mode blocks the request before vault or network access:

```bash
python -m demo.scenario_hard
```

Serve the injected booking page separately with:

```bash
python -m http.server 8080 --directory mock_site
```
