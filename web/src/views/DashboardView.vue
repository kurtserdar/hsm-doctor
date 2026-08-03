<script setup lang="ts">
import { ref, watch } from "vue";
import { scan } from "../api";
import { store } from "../store";
import { t } from "../i18n";
import type { ScanReport } from "../types";

const report = ref<ScanReport | null>(null);
const loading = ref(false);
const error = ref("");

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

function scoreClass(score: number): string {
  if (score >= 90) return "good";
  if (score >= 70) return "warn";
  return "bad";
}
</script>

<template>
  <div v-if="error" class="error">{{ error }}</div>
  <p v-if="loading" class="muted">{{ t("common.scanning") }}</p>

  <template v-if="report">
    <div class="card grid">
      <div class="stat">
        <div class="score" :class="scoreClass(report.score)">
          {{ report.score }}<span style="font-size: 1rem">/100</span>
        </div>
        <div class="label">{{ t("dash.healthScore") }}</div>
      </div>
      <div class="stat">
        <div class="value">{{ report.counts.private_keys }}</div>
        <div class="label">{{ t("dash.privateKeys") }}</div>
      </div>
      <div class="stat">
        <div class="value">{{ report.counts.public_keys }}</div>
        <div class="label">{{ t("dash.publicKeys") }}</div>
      </div>
      <div class="stat">
        <div class="value">{{ report.counts.secret_keys }}</div>
        <div class="label">{{ t("dash.secretKeys") }}</div>
      </div>
      <div class="stat">
        <div class="value">{{ report.counts.certificates }}</div>
        <div class="label">{{ t("dash.certificates") }}</div>
      </div>
      <div class="stat">
        <div class="value">{{ (report.findings ?? []).length }}</div>
        <div class="label">{{ t("dash.findings") }}</div>
      </div>
    </div>

    <div v-if="!report.inventory.logged_in" class="note">
      {{ t("dash.noPin") }}
    </div>

    <div v-if="report.vendor" class="card">
      <h2 style="margin-top: 0; font-size: 1rem">
        {{ t("dash.vendor", { provider: report.vendor.provider }) }}
        <span v-if="report.vendor.experimental" class="badge medium" style="font-weight: 400">
          {{ t("dash.experimental") }}
        </span>
      </h2>
      <div class="grid">
        <div v-if="report.vendor.device?.disk_percent !== undefined" class="stat">
          <div class="value">{{ report.vendor.device.disk_percent.toFixed(0) }}%</div>
          <div class="label">{{ t("dash.disk") }}</div>
        </div>
        <div v-if="report.vendor.tamper" class="stat">
          <div class="value">
            <span v-if="report.vendor.tamper.tampered" class="badge expired">{{ t("dash.tampered") }}</span>
            <span v-else class="badge ok">{{ t("dash.clear") }}</span>
          </div>
          <div class="label">{{ t("dash.tamper") }}</div>
        </div>
        <div v-if="report.vendor.ha" class="stat">
          <div class="value">
            {{ (report.vendor.ha.members ?? []).filter((m) => m.up).length }}/{{
              (report.vendor.ha.members ?? []).length
            }}
          </div>
          <div class="label">{{ t("dash.haUp") }}</div>
        </div>
        <div v-if="report.vendor.partitions?.length" class="stat">
          <div class="value">{{ report.vendor.partitions.length }}</div>
          <div class="label">{{ t("dash.partitions") }}</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2 style="margin-top: 0; font-size: 1rem">
        {{ t("dash.findingsTitle") }}
        <span v-if="report.rule_packs?.length" class="muted" style="font-weight: 400; font-size: 0.8rem">
          — {{ t("dash.rulePacks", { packs: report.rule_packs.join(", ") }) }}
        </span>
      </h2>
      <p v-if="!(report.findings ?? []).length" class="muted">
        {{ t("dash.noFindings") }}
      </p>
      <div v-else class="tablebox">
        <table>
          <thead>
            <tr>
              <th>{{ t("th.severity") }}</th>
              <th>{{ t("th.rule") }}</th>
              <th>{{ t("th.finding") }}</th>
              <th>{{ t("th.objectDetail") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(f, i) in report.findings" :key="i">
              <td><span class="badge" :class="f.severity">{{ f.severity }}</span></td>
              <td><code>{{ f.rule_id }}</code></td>
              <td>{{ f.title }}</td>
              <td>
                {{ f.object }}
                <div v-if="f.detail" class="muted">{{ f.detail }}</div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </template>
</template>
