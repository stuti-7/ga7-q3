// POST /terraform/plan
// Deterministic policy-as-code gate for a single normalized Terraform
// resource change. No LLM involved — pure structural / value rules,
// evaluated independently per request.

const WORKSPACE = "prod-y5xvuw";
const REQUIRED_LABELS = {
  owner: "student-bm9g9",
  environment: "production",
  cost_center: "cc-4cc0",
};
const VALID_BACKENDS = ["gcs", "s3", "azurerm", "remote"];
const DELETE_GUARDED_TYPES = ["storage_bucket", "sql_database", "persistent_disk"];

const EXACT_VERSION_RE = /^(=\s*)?\d+\.\d+\.\d+$/;
const PESSIMISTIC_VERSION_RE = /^~>\s*\d+(\.\d+){1,2}$/;

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function isString(v) {
  return typeof v === "string";
}
function isBoolean(v) {
  return typeof v === "boolean";
}

function validateShape(body) {
  if (!isPlainObject(body)) return false;
  if (!isString(body.environment)) return false;

  if (!isPlainObject(body.state)) return false;
  if (!isString(body.state.backend)) return false;
  if (!isBoolean(body.state.locked)) return false;

  if (!isString(body.providerVersion)) return false;
  if (!isBoolean(body.destroyApproved)) return false;

  const r = body.resource;
  if (!isPlainObject(r)) return false;
  if (!isString(r.address)) return false;
  if (!isString(r.type)) return false;
  if (!isString(r.action) || !["create", "update", "delete"].includes(r.action)) return false;

  if (!isPlainObject(r.labels)) return false;
  for (const v of Object.values(r.labels)) {
    if (!isString(v)) return false;
  }

  if (!(r.secret === null || isString(r.secret))) return false;
  if (!isBoolean(r.forceDestroy)) return false;

  return true;
}

function decide(body) {
  // 1) Type validation
  if (!validateShape(body)) {
    return { decision: "reject", reason: "INVALID_PLAN" };
  }

  const { environment, state, providerVersion, destroyApproved, resource } = body;

  // 2) Workspace / environment match
  if (environment !== WORKSPACE) {
    return { decision: "reject", reason: "ENVIRONMENT_MISMATCH" };
  }

  // 3) State safety
  if (!VALID_BACKENDS.includes(state.backend) || state.locked !== true) {
    return { decision: "reject", reason: "STATE_UNSAFE" };
  }

  // 4) Provider version pinning
  const pv = providerVersion.trim();
  const pinned = EXACT_VERSION_RE.test(pv) || PESSIMISTIC_VERSION_RE.test(pv);
  if (!pinned) {
    return { decision: "reject", reason: "UNPINNED_PROVIDER" };
  }

  // 5) Required cost-ownership labels
  for (const [key, val] of Object.entries(REQUIRED_LABELS)) {
    if (resource.labels[key] !== val) {
      return { decision: "reject", reason: "MISSING_LABELS" };
    }
  }

  // 6) Secret handling
  if (resource.secret !== null) {
    const s = resource.secret;
    const prefix = "secret://";
    if (!(s.startsWith(prefix) && s.length > prefix.length)) {
      return { decision: "reject", reason: "PLAINTEXT_SECRET" };
    }
  }

  // 7) Destroy approval for guarded resource types
  if (resource.action === "delete" && DELETE_GUARDED_TYPES.includes(resource.type)) {
    if (destroyApproved !== true) {
      return { decision: "reject", reason: "DELETE_NOT_APPROVED" };
    }
  }

  // 8) Force-destroy never allowed on production storage buckets
  if (resource.type === "storage_bucket" && resource.forceDestroy === true) {
    return { decision: "reject", reason: "FORCE_DESTROY" };
  }

  return { decision: "approve", reason: "APPROVE" };
}

module.exports = (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(204).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ decision: "reject", reason: "INVALID_PLAN" });
  }

  let body = req.body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch (e) {
      return res.status(200).json({ decision: "reject", reason: "INVALID_PLAN" });
    }
  }

  const result = decide(body);
  return res.status(200).json(result);
};
