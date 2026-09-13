import { createStore } from "/js/AlpineStore.js";
import { callJsonApi } from "/js/api.js";
import { toastFrontendError } from "/components/notifications/notification-store.js";

export const store = createStore("samObservatory", {
  view: "Node", node: {}, catalog: null, events: [], review: null,
  loading: false, error: "", contextId: "", decisionId: "", acknowledgment: "",
  peer: "", tool: "", payload: "{}", dataClass: "public", query: "",
  stopping: false, stopConfirm: false, generation: 0, resumeAck: "", kind: "mcp",
  model: "", service: "", message: "", inference: null, inferenceResult: null,
  embassyName: "", embassyProject: "", embassyProfile: "", publication: null, deployment: null,
  embassyRuntime: null, publicationAck: false,
  nativePlan: null,
  async api(name, data = {}) {
    const context = globalThis.getContext?.() || "";
    if (!context) throw new Error("Open a chat to inspect its SAM passport.");
    if (this.contextId && this.contextId !== context) this.clear();
    this.contextId = context;
    const generation = this.generation;
    const result = await callJsonApi(`/plugins/sam_mesh/${name}`, { ...data, context_id: context });
    if (generation !== this.generation || context !== globalThis.getContext?.()) {
      const error = new Error("This response belongs to an earlier view.");
      error.stale = true; throw error;
    }
    if (result?.error_code) throw new Error(result.error_code.replaceAll("_", " "));
    return result;
  },
  clear() {
    this.generation++;
    this.node = {}; this.catalog = null; this.events = []; this.review = null;
    this.decisionId = ""; this.acknowledgment = ""; this.payload = "{}";
    this.stopConfirm = false;
    this.inference = null; this.inferenceResult = null; this.message = "";
    this.publication = null; this.deployment = null; this.nativePlan = null; this.resumeAck = "";
    this.embassyRuntime = null; this.publicationAck = false;
    this.embassyName = ""; this.embassyProject = ""; this.embassyProfile = "";
  },
  async run(action) {
    if (this.loading || this.stopping) return;
    this.loading = true; this.error = "";
    try { await action(); }
    catch (error) { if (!error.stale) { this.error = error.message || "SAM is unavailable."; toastFrontendError(this.error, "SAM Mesh"); } }
    finally { this.loading = false; }
  },
  scopeChanged() {
    const current = globalThis.getContext?.() || "";
    if (this.contextId && this.contextId !== current) this.clear();
    this.contextId = current;
  },
  async onOpen() { await this.refresh(); },
  cleanup() { this.clear(); },
  async refresh() {
    await this.run(async () => {
      if (this.view === "Catalog") this.catalog = await this.api("catalog", { query: this.query, kind: this.kind });
      else if (this.view === "Activity") this.events = (await this.api("audit")).events || [];
      else if (this.view === "Embassy") {
        this.deployment = await this.api("deployment_status");
        this.embassyRuntime = await this.api("publication_status");
        this.node = await this.api("status");
        this.embassyProject = this.node.scope?.project_name || "";
        this.embassyProfile = this.node.scope?.agent_profile || "";
      }
      else this.node = await this.api("status");
    });
  },
  async select(view) { this.view = view; await this.refresh(); },
  async inspect() {
    await this.run(async () => {
      this.review = await this.api("review", { decision_id: this.decisionId.trim() });
      this.acknowledgment = "";
    });
  },
  async preflight() {
    await this.run(async () => {
      const argumentsValue = JSON.parse(this.payload);
      this.review = await this.api("preflight", { peer_id: this.peer, tool_name: this.tool,
        arguments: argumentsValue, data_class: this.dataClass });
      this.decisionId = this.review.decision_id;
      this.payload = "{}"; this.acknowledgment = "";
    });
  },
  async approve() {
    await this.run(async () => {
      await this.api(this.review.kind === "inference" ? "inference_approve" : "approve", { decision_id: this.review.decision_id, acknowledgment: this.acknowledgment });
      this.review = await this.api("review", { decision_id: this.review.decision_id });
      this.acknowledgment = "";
    });
  },
  async revoke() {
    await this.run(async () => {
      await this.api("revoke", { decision_id: this.review.decision_id });
      this.review = null;
    });
  },
  async disconnect() {
    // Emergency stop must remain usable while a network refresh is in flight.
    this.error = ""; this.stopping = true;
    this.generation++;
    try {
      const result = await this.api("emergency_disconnect");
      this.node = { ...this.node, stopped: result.stopped };
      this.review = null; this.stopConfirm = false;
    } catch (error) { if (!error.stale) { this.error = error.message; toastFrontendError(this.error, "SAM Mesh"); } }
    finally { this.stopping = false; }
  },
  async resume() {
    await this.run(async () => {
      await this.api("resume", { acknowledgment: this.resumeAck });
      this.resumeAck = ""; this.review = null;
      this.node = await this.api("status");
    });
  },
  async profile() {
    await this.run(async () => { this.inference = await this.api("inference_profile", { model: this.model }); });
  },
  async probe(stream) {
    await this.run(async () => { this.inference = await this.api("inference_probe", { model: this.model, stream }); });
  },
  async prepareInference() {
    await this.run(async () => {
      this.review = await this.api("inference_preflight", { peer_id: this.peer, service: this.service,
        model: this.model, message: this.message, data_class: this.dataClass });
      this.decisionId = this.review.decision_id; this.message = ""; this.acknowledgment = "";
      this.inferenceResult = null;
    });
  },
  async invokeInference() {
    await this.run(async () => {
      this.inferenceResult = await this.api("inference_invoke", { decision_id: this.review.decision_id });
      this.review = null;
    });
  },
  async planPublication() {
    this.publicationAck = false;
    await this.run(async () => { this.publication = await this.api("publication_plan", { service: {
      name: this.embassyName, project: this.embassyProject, agent_profile: this.embassyProfile,
    } }); });
  },
  async startPublication() {
    if (!this.publicationAck || !this.publication?.service) return;
    const service = structuredClone(this.publication.service);
    this.publicationAck = false;
    await this.run(async () => {
      this.publication = await this.api("publication_start", { service, acknowledgment: "PUBLISH" });
      this.embassyRuntime = await this.api("publication_status");
    });
  },
  async closePublication(name) {
    await this.run(async () => {
      this.publication = await this.api("publication_close", { name });
      this.embassyRuntime = await this.api("publication_status");
      this.publicationAck = false;
    });
  },
  async planNative() {
    await this.run(async () => { this.nativePlan = await this.api("native_mcp_plan"); });
  },
  async exportAudit() {
    await this.run(async () => {
      const result = await this.api("audit", { export: true });
      const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
      const link = document.createElement("a"); link.href = url; link.download = "sam-audit.json";
      link.click(); URL.revokeObjectURL(url);
    });
  },
  fact(value) {
    return ({ verified_now: "Verified now", cached: "Cached", partial: "Partial discovery",
      unreachable: "Unreachable", schema_changed: "Schema changed", unsupported: "Unsupported" })[value] || "Not checked";
  },
  json(value) { return JSON.stringify(value, null, 2); },
});
