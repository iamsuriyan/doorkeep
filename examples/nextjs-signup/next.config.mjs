import { fileURLToPath } from "node:url";
import { withDoorkeepProxy } from "@doorkeep/next";

// Proxies /_dk/* to DOORKEEP_URL so the snippet loads from this origin.
// turbopack.root pins the monorepo root (where node_modules lives), so the
// build does not depend on guessing it from the environment.
export default withDoorkeepProxy({
  turbopack: { root: fileURLToPath(new URL("../..", import.meta.url)) },
});
