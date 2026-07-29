import { reactive } from "vue";
import { ApiError, discover, serverInfo } from "./api";
import type { ModuleInfo, SlotInfo } from "./types";

// Minimal shared state: server mode, the discovered module, its slots and
// the slot the user is working with. Small enough that a store library is
// not needed.
export const store = reactive({
  mode: "" as "" | "local" | "central",
  module: null as ModuleInfo | null,
  slots: [] as SlotInfo[],
  selectedSlot: null as number | null,
  loading: false,
  error: "",
  authRequired: false,

  async load() {
    this.loading = true;
    this.error = "";
    this.authRequired = false;
    try {
      const info = await serverInfo();
      this.mode = info.mode;
      if (info.mode !== "local") {
        return;
      }
      const res = await discover();
      this.module = res.module;
      this.slots = res.slots;
      const withToken = res.slots.filter((s) => s.token_present);
      if (this.selectedSlot === null && withToken.length > 0) {
        this.selectedSlot = withToken[0].id;
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        this.authRequired = true;
        return;
      }
      this.error = e instanceof Error ? e.message : String(e);
    } finally {
      this.loading = false;
    }
  },
});
