<script setup lang="ts">
import { ref } from "vue";
import { runBench } from "../api";
import { store } from "../store";
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
</script>

<template>
  <div class="note">
    Benchmarks generate sustained load. Every run is capped by duration and
    an absolute operation budget, but avoid running them against production
    HSMs serving live traffic.
  </div>

  <div class="formrow">
    <div>
      <label>Duration (ms, max 60000)</label>
      <input v-model.number="durationMs" type="number" min="100" style="width: 8rem" />
    </div>
    <div>
      <label>Max ops per primitive</label>
      <input v-model.number="maxOps" type="number" min="1" style="width: 8rem" />
    </div>
    <div>
      <label>Sessions (max 32)</label>
      <input v-model.number="sessions" type="number" min="1" max="32" style="width: 6rem" />
    </div>
    <button class="primary" :disabled="running || store.selectedSlot === null" @click="run">
      {{ running ? "Running…" : "Run benchmark" }}
    </button>
  </div>

  <div v-if="error" class="error">{{ error }}</div>

  <div v-if="result" class="card">
    <div class="tablebox">
      <table>
        <thead>
          <tr>
            <th>Primitive</th>
            <th>Throughput</th>
            <th>Operations</th>
            <th>Elapsed</th>
            <th>Note</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(m, i) in result.measurements" :key="i">
            <td>{{ m.name }}</td>
            <td>
              <strong v-if="m.supported && !m.error">
                {{ m.ops_per_sec.toFixed(1) }} ops/sec
              </strong>
              <span v-else class="badge skip">NOT SUPPORTED</span>
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
