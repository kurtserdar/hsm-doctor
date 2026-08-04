<script setup lang="ts">
import { ref } from "vue";
import { runTest } from "../api";
import { store } from "../store";
import { t } from "../i18n";
import type { TestResult } from "../types";

const profile = ref("sign-verify");
const result = ref<TestResult | null>(null);
const running = ref(false);
const error = ref("");

async function run() {
  if (store.selectedSlot === null) return;
  running.value = true;
  error.value = "";
  result.value = null;
  try {
    result.value = await runTest(store.selectedSlot, profile.value);
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    running.value = false;
  }
}

function badgeClass(status: string): string {
  if (status === "PASS") return "pass";
  if (status === "FAIL") return "fail";
  return "skip";
}

function ms(ns?: number): string {
  if (!ns) return "";
  return `${(ns / 1e6).toFixed(0)} ms`;
}
</script>

<template>
  <p class="muted">
    {{ t("tests.note") }}
  </p>

  <div class="formrow">
    <div>
      <label>{{ t("tests.profile") }}</label>
      <select v-model="profile">
        <option value="sign-verify">sign-verify</option>
      </select>
    </div>
    <button class="primary" :disabled="running || store.selectedSlot === null" @click="run">
      {{ running ? t("common.running") : t("tests.run") }}
    </button>
  </div>

  <div v-if="error" class="error">{{ error }}</div>

  <div v-if="running" class="card">
    <div v-for="n in 3" :key="n" class="skeleton skel-line" style="width: 100%; height: 1.3rem; margin-bottom: 0.6rem"></div>
  </div>

  <div v-if="result" class="card">
    <div class="tablebox">
      <table>
        <thead>
          <tr>
            <th>{{ t("th.step") }}</th>
            <th>{{ t("th.status") }}</th>
            <th>{{ t("th.duration") }}</th>
            <th>{{ t("th.detail") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(s, i) in result.steps" :key="i">
            <td>{{ s.name }}</td>
            <td><span class="badge" :class="badgeClass(s.status)">{{ s.status }}</span></td>
            <td class="muted">{{ ms(s.duration_ns) }}</td>
            <td class="muted">{{ s.detail }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
