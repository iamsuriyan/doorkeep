import { withDoorkeepProxy } from "@doorkeep/next";

// Proxies /_dk/* to DOORKEEP_URL so the snippet loads from this origin.
export default withDoorkeepProxy({});
