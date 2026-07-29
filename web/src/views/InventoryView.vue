<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { scan } from "../api";
import { store } from "../store";
import type { InventoryObject, ScanReport } from "../types";

const report = ref<ScanReport | null>(null);
const loading = ref(false);
const error = ref("");
const classFilter = ref("all");

async function load() {
  if (store.selectedSlot === null) return;
  loading.value = true;
  error.value = "";
  try {
    report.value = await scan(store.selectedSlot);
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

watch(() => store.selectedSlot, load, { immediate: true });

const objects = computed<InventoryObject[]>(() => {
  const all = report.value?.inventory.objects ?? [];
  if (classFilter.value === "all") return all;
  return all.filter((o) => o.class === classFilter.value);
});

function flags(o: InventoryObject): string {
  const out: string[] = [];
  if (o.sensitive === false) out.push("sensitive=false");
  if (o.extractable) out.push("extractable");
  if (o.sign) out.push("sign");
  if (o.verify) out.push("verify");
  if (o.encrypt) out.push("encrypt");
  if (o.decrypt) out.push("decrypt");
  if (o.wrap) out.push("wrap");
  if (o.unwrap) out.push("unwrap");
  if (o.derive) out.push("derive");
  return out.join(", ");
}
</script>

<template>
  <div v-if="error" class="error">{{ error }}</div>
  <p v-if="loading" class="muted">Loading inventory…</p>

  <template v-if="report">
    <div class="formrow">
      <div>
        <label>Object class</label>
        <select v-model="classFilter">
          <option value="all">All classes</option>
          <option value="private-key">Private keys</option>
          <option value="public-key">Public keys</option>
          <option value="secret-key">Secret keys</option>
          <option value="certificate">Certificates</option>
        </select>
      </div>
      <div class="muted" style="padding-bottom: 0.5rem">
        {{ objects.length }} object(s)
      </div>
    </div>

    <div class="card">
      <div class="tablebox">
        <table>
          <thead>
            <tr>
              <th>Class</th>
              <th>Label</th>
              <th>ID</th>
              <th>Type</th>
              <th>Size</th>
              <th>Flags</th>
              <th>Certificate</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(o, i) in objects" :key="i">
              <td>{{ o.class }}</td>
              <td>{{ o.label }}</td>
              <td><code v-if="o.id">{{ o.id }}</code></td>
              <td>{{ o.key_type }}<template v-if="o.curve"> {{ o.curve }}</template></td>
              <td>{{ o.key_bits || "" }}</td>
              <td class="muted">{{ flags(o) }}</td>
              <td>
                <template v-if="o.certificate">
                  {{ o.certificate.subject }}
                  <div class="muted">
                    expires {{ o.certificate.not_after.slice(0, 10) }}
                  </div>
                </template>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </template>
</template>
