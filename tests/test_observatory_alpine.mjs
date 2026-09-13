import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import test from "node:test";

// Point at the host's installed Alpine and AlpineStore sources. No replacement
// reactivity engine: this exercises the same proxy boundary as native Agent Zero.
const alpinePath = process.env.SAM_TEST_ALPINE_JS;
const storePath = process.env.SAM_TEST_ALPINE_STORE_JS;
const configured = Boolean(alpinePath || storePath);
test("native Alpine publication sends an independent exact reviewed JSON snapshot", {skip: !configured && "set SAM_TEST_ALPINE_JS and SAM_TEST_ALPINE_STORE_JS to host sources"}, async () => {
  assert.ok(alpinePath && storePath && existsSync(alpinePath) && existsSync(storePath), "both configured host sources must exist");
  const browser = {
    window: null,
    document: { addEventListener() {}, createElement: () => ({}) },
    Element: class {},
    MutationObserver: class { observe() {} disconnect() {} },
    // Alpine registers startup here; DOM scanning is unnecessary for stores.
    queueMicrotask() {},
    console,
  };
  browser.window = browser;
  runInNewContext(readFileSync(alpinePath, "utf8"), browser);
  const hostSource = readFileSync(storePath, "utf8").replace(/^export /gm, "");
  const createStore = new Function("globalThis", "document", hostSource + "; return createStore;")(browser, browser.document);
  const source = readFileSync(new URL("../webui/observatory-store.js", import.meta.url), "utf8")
    .replace(/^import .*;\n/gm, "").replace("export const store", "const store");
  const calls = [], errors = [];
  browser.getContext = () => "native-chat";
  let unblock;
  const pending = new Promise(resolve => { unblock = resolve; });
  const store = new Function("createStore", "callJsonApi", "toastFrontendError", "globalThis", source + "; return store;")
    (createStore, async (path, data) => { calls.push({path, data}); await pending; return { services: [] }; }, error => errors.push(error), browser);
  const reviewed = { name: "reviewed-desk", project: "research", agent_profile: "specialist", agent_tool_policy: ["response"], max_input_bytes: 4096 };
  store.publication = {service: reviewed};
  assert.notEqual(browser.Alpine.raw(store.publication.service), store.publication.service);
  assert.throws(() => structuredClone(store.publication.service), {name: "DataCloneError"});
  store.publicationAck = true;
  store.embassyName = "edited-after-review";
  const start = store.startPublication();
  try {
    assert.equal(calls.length, 1);
    assert.equal(calls[0].path, "/plugins/sam_mesh/publication_start");
    assert.deepEqual(calls[0].data.service, reviewed);
    assert.equal(calls[0].data.acknowledgment, "PUBLISH");
    assert.equal(store.publicationAck, false);
    store.publication.service.agent_tool_policy.push("changed-after-request");
    assert.deepEqual(calls[0].data.service.agent_tool_policy, ["response"]);
  } finally {
    unblock();
    await start;
  }
  assert.deepEqual(errors, []);
});
