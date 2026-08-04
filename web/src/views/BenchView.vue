<script setup lang="ts">
import { computed, ref } from "vue";
import { runBench } from "../api";
import { store } from "../store";
import { t } from "../i18n";
import type { BenchResult } from "../types";

const durationMs = ref(3000);
const maxOps = ref(5000);
const sessions = ref(1);
const result = ref<BenchResult | null>(null);
const running = ref(false);
const error = ref("");

async function run() {
  if (store.selectedSlot === null) return;
  running.value = true;
  error.value = "";
  result.value = null;
  try {
    result.value = await runBench(store.selectedSlot, {
      duration_ms: durationMs.value,
      max_ops: maxOps.value,
      sessions: sessions.value,
    });
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    running.value = false;
  }
}

const maxThroughput = computed(() => {
  const ms = result.value?.measurements ?? [];
  return Math.max(1, ...ms.filter((m) => m.supported && !m.error).map((m) => m.ops_per_sec));
});
</script>

<template>
  <div class="note">
    {{ t("bench.note") }}
  </div>

  <div class="formrow">
    <div>
      <label>{{ t("bench.duration") }}</label>
      <input v-model.number="durationMs" type="number" min="100" style="width: 8rem" />
    </div>
    <div>
      <label>{{ t("bench.maxOps") }}</label>
      <input v-model.number="maxOps" type="number" min="1" style="width: 8rem" />
    </div>
    <div>
      <label>{{ t("bench.sessions") }}</label>
      <input v-model.number="sessions" type="number" min="1" max="32" style="width: 6rem" />
    </div>
    <button class="primary" :disabled="running || store.selectedSlot === null" @click="run">
      {{ running ? t("common.running") : t("bench.run") }}
    </button>
  </div>

  <div v-if="error" class="error">{{ error }}</div>

  <div v-if="running" class="card">
    <div v-for="n in 4" :key="n" class="skeleton skel-line" style="width: 100%; height: 1.3rem; margin-bottom: 0.6rem"></div>
  </div>

  <div v-if="result" class="card">
    <div class="tablebox">
      <table>
        <thead>
          <tr>
            <th>{{ t("th.primitive") }}</th>
            <th>{{ t("th.throughput") }}</th>
            <th>{{ t("th.operations") }}</th>
            <th>{{ t("th.elapsed") }}</th>
            <th>{{ t("th.note") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(m, i) in result.measurements" :key="i">
            <td>{{ m.name }}</td>
            <td>
              <div v-if="m.supported && !m.error" class="minibar">
                <div class="track"><span :style="{ width: (m.ops_per_sec / maxThroughput) * 100 + '%' }"></span></div>
                <strong>{{ t("bench.opsPerSec", { n: m.ops_per_sec.toFixed(1) }) }}</strong>
              </div>
              <span v-else class="badge skip">{{ t("bench.notSupported") }}</span>
            </td>
            <td class="muted">{{ m.supported ? m.ops : "" }}</td>
            <td class="muted">
              {{ m.supported ? (m.elapsed_ns / 1e6).toFixed(0) + " ms" : "" }}
            </td>
            <td class="muted">{{ m.error }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
