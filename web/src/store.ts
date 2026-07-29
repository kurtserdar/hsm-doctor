import { reactive } from "vue";
import { discover } from "./api";
import type { ModuleInfo, SlotInfo } from "./types";

// Minimal shared state: the discovered module, its slots and the slot the
// user is working with. Small enough that a store library is not needed.
export const store = reactive({
  module: null as ModuleInfo | null,
  slots: [] as SlotInfo[],
  selectedSlot: null as number | null,
  loading: false,
  error: "",

  async load() {
    this.loading = true;
    this.error = "";
    try {
      const res = await discover();
      this.module = res.module;
      this.slots = res.slots;
      const withToken = res.slots.filter((s) => s.token_present);
      if (this.selectedSlot === null && withToken.length > 0) {
        this.selectedSlot = withToken[0].id;
      }
    } catch (e) {
      this.error = e instanceof Error ? e.message : String(e);
    } finally {
      this.loading = false;
    }
  },
});
