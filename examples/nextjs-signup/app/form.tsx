"use client";
import { useActionState } from "react";
import { Doorkeep } from "@doorkeep/next/client";
import { signup } from "./actions";

export function SignupForm({ sitekey }: { sitekey: string }) {
  const [state, action, pending] = useActionState(signup, null);
  return (
    <>
      <form action={action} id="f">
        <p><label>Name <input name="name" id="name" required /></label></p>
        <p><label>Email <input name="email" id="email" type="email" required /></label></p>
        <Doorkeep action="signup" sitekey={sitekey} />
        <button id="go" disabled={pending}>Sign up</button>
      </form>
      {state && <p id="result" data-ok={String(state.ok)} data-risk={String(state.risk)} data-reasons={(state.reasons || []).join(",")}>{state.message}</p>}
    </>
  );
}
