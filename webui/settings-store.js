import { createStore } from "/js/AlpineStore.js";
import { openModal } from "/js/modals.js";
import { toastFrontendError } from "/components/notifications/notification-store.js";

// The host's pluginSettingsPrototype owns config, scope, saving and reset.
// Attach only this plugin's modal action to that modal's context instance.
export const store = createStore("samSettings", {
  modeChanged(config) {
    if (config.passport.mode === "sovereign") {
      Object.assign(config.transport, {
        type: "http", base_url: "http://mesh.sam.alt", socket_path: "",
        token_secret_name: "", token_file: "", allowed_origins: ["http://mesh.sam.alt"],
      });
    }
  },
  bind(context) {
    context.samMesh = {
      async openObservatory() {
        try {
          if (context.hasUnsavedChanges) {
            throw new Error("Save the settings before opening the Observatory.");
          }
          if (!globalThis.getContext?.()) {
            throw new Error("Open a chat to inspect its SAM passport.");
          }
          await openModal("/plugins/sam_mesh/webui/observatory.html");
        } catch (error) {
          toastFrontendError(error.message || "Unable to open Observatory.", "SAM Mesh");
        }
      },
    };
  },
});
