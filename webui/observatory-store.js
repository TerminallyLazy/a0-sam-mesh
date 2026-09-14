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
  nativePlan: null, opened: false, refreshPending: false, setupTimer: null,
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
    finally {
      this.loading = false;
      if (this.refreshPending && this.opened) {
        this.refreshPending = false;
        queueMicrotask(() => this.refresh());
      }
    }
  },
  scopeChanged() {
    const current = globalThis.getContext?.() || "";
    if (this.contextId === current) return;
    this.clear();
    this.contextId = current;
    if (this.opened && current) {
      if (this.loading) this.refreshPending = true;
      else queueMicrotask(() => this.refresh());
    }
  },
  async onOpen() { this.opened = true; await this.refresh(); },
  cleanup() { clearTimeout(this.setupTimer); this.setupTimer = null; this.opened = false; this.refreshPending = false; this.clear(); },
  async refresh() {
    if (!globalThis.getContext?.()) return;
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
      clearTimeout(this.setupTimer);
      if (this.opened && ["installing", "starting"].includes(this.node.setup?.status)) {
        this.setupTimer = setTimeout(() => this.refresh(), 2000);
      }
    });
  },
  async select(view) {
    this.view = view;
    if (this.loading) this.refreshPending = true;
    else await this.refresh();
  },
  get catalogEntries() { return Array.isArray(this.catalog?.data) ? this.catalog.data.filter(entry => entry && typeof entry === "object" && !Array.isArray(entry)) : []; },
  async openSettings() {
    try {
      const { store } = await import("/components/plugins/plugin-settings-store.js");
      await store.openConfig("sam_mesh", this.node.scope?.project_name || "", this.node.scope?.agent_profile || "");
    } catch (error) { toastFrontendError("Open SAM Mesh settings from Plugins.", "SAM Mesh"); }
  },
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
    this.publicationAck = false;
    await this.run(async () => {
      const service = JSON.parse(JSON.stringify(this.publication.service));
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
  get connectionTitle() {
    if (!this.contextId) return "Choose a chat";
    if (this.node.ready) return this.node.connection === "managed" ? "Local mesh is ready" : "Connected to your mesh";
    if (this.node.setup?.status === "installing") return "Installing SAM";
    if (this.node.setup?.status === "starting") return "Starting your local mesh";
    if (this.node.setup?.status === "failed") return "Local mesh needs attention";
    if (this.loading && !this.node.status) return "Checking your connection";
    return "Connect your mesh";
  },
  get connectionDetail() {
    if (!this.contextId) return "Select a chat to view its connection, services, and approvals.";
    if (this.node.ready) return this.node.connection === "managed" ? "Your private node is running in Agent Zero. Add or connect services to make them available here." : "The configured SAM node answered the authenticated probe.";
    if (this.node.setup?.status === "installing") return "Downloading and verifying the published SAM binaries. This happens automatically.";
    if (this.node.setup?.status === "starting") return "Creating the private local mesh and connecting your node. Your identity is preserved on restart.";
    if (this.node.setup?.status === "failed") return "Automatic setup could not finish. Save Local mesh in connection settings to retry.";
    return "Choose Local mesh in settings to create a node automatically, or enter an existing node connection.";
  },
  fact(value) {
    return ({ setup_required: "Setup", verified_now: "Verified now", cached: "Cached", partial: "Partial discovery",
      unreachable: "Unreachable", schema_changed: "Schema changed", unsupported: "Unsupported" })[value] || "Not checked";
  },
  json(value) { return JSON.stringify(value, null, 2); },
});
