---
name: announce-booking
description: Speak sanitized Warden outcomes with ElevenLabs.
---

# Announce Booking

Speak only a sanitized Warden outcome. Do not accept arbitrary narration.

## Procedure

1. Accept only `status`, `amount`, and an optional public blocked `reason`.
2. From the Warden project root run:

   ```bash
   python3 skills/announce-booking/scripts/announce.py \
     --status <success-or-blocked> --amount <inr-amount> \
     --reason "<blocked-reason-if-any>"
   ```

3. Return the printed audio path. Never read or repeat charge IDs, subscription
   IDs, secret references, API keys, provider errors, or arbitrary agent text.

The bundled script constructs the spoken sentence from an allowlisted schema
before calling ElevenLabs.
