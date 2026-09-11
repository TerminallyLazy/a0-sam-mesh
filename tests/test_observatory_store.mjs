import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../webui/observatory-store.js", import.meta.url), "utf8")
  .replace(/^import .*;\n/gm, "")
  .replace("export const store", "const store");
function fixture(api) {
  let context = "chat-a";
  globalThis.getContext = () => context;
  const errors = [];
  const store = new Function("createStore", "callJsonApi", "toastFrontendError", source + "; return store;")
    ((_name, value) => value, api, (error) => errors.push(error));
  return { store, errors, switchChat: value => { context = value; store.scopeChanged(); } };
}
test("an in-flight refresh cannot overwrite emergency stop", async () => {
  let resolveStatus;
  const f = fixture(async (path) => path.endsWith("/status")
    ? new Promise(resolve => { resolveStatus = resolve; }) : { stopped: true, status: "verified_now" });
  f.store.node = { status: "unreachable" };
  const refresh = f.store.refresh();
  await f.store.disconnect();
  resolveStatus({ stopped: false, status: "verified_now" });
  await refresh;
  assert.equal(f.store.node.stopped, true);
  assert.equal(f.store.node.status, "unreachable");
  assert.deepEqual(f.errors, []);
});
test("a scope switch clears protected data and discards the old response", async () => {
  let respond;
  const f = fixture(() => new Promise(resolve => { respond = resolve; }));
  const call = f.store.refresh();
  f.store.message = "protected-sentinel";
  f.store.inferenceResult = { response: "protected-sentinel" };
  f.switchChat("chat-b");
  respond({ endpoint: "old-scope" });
  await call;
  assert.equal(f.store.message, "");
  assert.equal(f.store.inferenceResult, null);
  assert.deepEqual(f.store.node, {});
  assert.deepEqual(f.errors, []);
});
test("inference approval uses the dedicated endpoint", async () => {
  const calls = [];
  const f = fixture(async (path, data) => { calls.push({ path, data }); return { approved: true }; });
  f.store.review = { kind: "inference", decision_id: "decision" };
  f.store.acknowledgment = "APPROVE";
  await f.store.approve();
  assert.equal(calls[0].path, "/plugins/sam_mesh/inference_approve");
  assert.equal(calls[0].data.context_id, "chat-a");
  assert.equal(f.store.acknowledgment, "");
});

test("closing Observatory clears protected data and rejects an outstanding response", async () => {
  let respond;
  const f = fixture(() => new Promise(resolve => { respond = resolve; }));
  const pending = f.store.refresh();
  f.store.payload = "protected-arguments";
  f.store.message = "protected-message";
  f.store.cleanup();
  respond({ endpoint: "closed-view" });
  await pending;
  assert.equal(f.store.payload, "{}");
  assert.equal(f.store.message, "");
  assert.deepEqual(f.store.node, {});
  assert.deepEqual(f.errors, []);
});

const settingsSource = readFileSync(new URL("../webui/settings-store.js", import.meta.url), "utf8")
  .replace(/^import .*;\n/gm, "")
  .replace("export const store", "const store");
test("settings actions use their owning modal context without changing its config", async () => {
  const opened = [], errors = [];
  const settings = new Function("createStore", "openModal", "toastFrontendError", settingsSource + "; return store;")
    ((_name, value) => value, async path => opened.push(path), error => errors.push(error));
  globalThis.getContext = () => "active-chat";
  const saved = { settings: { project: "one" }, hasUnsavedChanges: false };
  const unsaved = { settings: { project: "two" }, hasUnsavedChanges: true };
  settings.bind(saved);
  settings.bind(unsaved);
  await unsaved.samMesh.openObservatory();
  assert.equal(opened.length, 0);
  assert.match(errors[0], /Save the settings/);
  await saved.samMesh.openObservatory();
  assert.deepEqual(opened, ["/plugins/sam_mesh/webui/observatory.html"]);
  assert.deepEqual(saved.settings, { project: "one" });
  assert.deepEqual(unsaved.settings, { project: "two" });
  globalThis.getContext = () => "";
  await saved.samMesh.openObservatory();
  assert.equal(opened.length, 1);
  assert.match(errors[1], /Open a chat/);
});
