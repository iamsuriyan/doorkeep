# doorkeep + Next.js signup example

```sh
export DOORKEEP_URL=http://127.0.0.1:8080        # where doorkeep listens
export DOORKEEP_SITE_KEY=dk_pk_...               # from `doorkeep site create`
export DOORKEEP_SECRET=dk_sk_...
pnpm build && pnpm start
```

- `next.config.mjs` uses `withDoorkeepProxy` so the snippet and API load from
  this origin under `/_dk/`.
- `app/form.tsx` places `<Doorkeep action="signup" />` inside the form.
- `app/actions.ts` calls `verifyDoorkeep(form, { action: "signup" })` in a
  Server Action; it throws `DoorkeepVerifyError` unless the outcome is allow.
