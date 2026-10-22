import { SignupForm } from "./form";

// The site key is runtime configuration, read on the server per request.
export const dynamic = "force-dynamic";

export default function Page() {
  return (
    <main>
      <h1>Create account</h1>
      <SignupForm sitekey={process.env.DOORKEEP_SITE_KEY || ""} />
    </main>
  );
}
