<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { scan } from "../api";
import { store } from "../store";
import { t } from "../i18n";
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

// Attribute flags, marking the risky ones (extractable, non-sensitive).
function flags(o: InventoryObject): { name: string; risk: boolean }[] {
  const out: { name: string; risk: boolean }[] = [];
  if (o.sensitive === false) out.push({ name: "sensitive=false", risk: true });
  if (o.extractable) out.push({ name: "extractable", risk: true });
  for (const k of ["sign", "verify", "encrypt", "decrypt", "wrap", "unwrap", "derive"] as const) {
    if (o[k]) out.push({ name: k, risk: false });
  }
  return out;
}
</script>

<template>
  <div v-if="error" class="error">{{ error }}</div>

  <div v-if="loading && !report" class="card">
    <div v-for="n in 6" :key="n" class="skeleton skel-line" style="width: 100%; height: 1.3rem; margin-bottom: 0.6rem"></div>
  </div>

  <template v-if="report">
    <div class="formrow">
      <div>
        <label>{{ t("inv.objectClass") }}</label>
        <select v-model="classFilter">
          <option value="all">{{ t("inv.allClasses") }}</option>
          <option value="private-key">{{ t("inv.privateKeys") }}</option>
          <option value="public-key">{{ t("inv.publicKeys") }}</option>
          <option value="secret-key">{{ t("inv.secretKeys") }}</option>
          <option value="certificate">{{ t("inv.certificates") }}</option>
        </select>
      </div>
      <div class="muted">{{ t("inv.objectCount", { n: objects.length }) }}</div>
    </div>

    <div class="card">
      <div v-if="objects.length === 0" class="empty">{{ t("inv.objectCount", { n: 0 }) }}</div>
      <div v-else class="tablebox">
        <table>
          <thead>
            <tr>
              <th>{{ t("th.class") }}</th>
              <th>{{ t("th.label") }}</th>
              <th>{{ t("th.id") }}</th>
              <th>{{ t("th.type") }}</th>
              <th>{{ t("th.size") }}</th>
              <th>{{ t("th.flags") }}</th>
              <th>{{ t("th.certificate") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(o, i) in objects" :key="i">
              <td>{{ o.class }}</td>
              <td>{{ o.label }}</td>
              <td><code v-if="o.id">{{ o.id }}</code></td>
              <td>{{ o.key_type }}<template v-if="o.curve"> {{ o.curve }}</template></td>
              <td>{{ o.key_bits || "" }}</td>
              <td>
                <span class="codes">
                  <code v-for="(f, j) in flags(o)" :key="j" :class="{ risk: f.risk }">{{ f.name }}</code>
                </span>
              </td>
              <td>
                <template v-if="o.certificate">
                  {{ o.certificate.subject }}
                  <div class="muted">
                    {{ t("inv.expires", { date: o.certificate.not_after.slice(0, 10) }) }}
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
