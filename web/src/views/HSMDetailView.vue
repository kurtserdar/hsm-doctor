<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { hsmDrift, hsmRegressions, hsmScan, hsmScans } from "../api";
import Sparkline from "../components/Sparkline.vue";
import { t } from "../i18n";
import type { DriftEvent, RegressionEvent, ScanReport, ScanSummary } from "../types";

const route = useRoute();
const hsmID = Number(route.params.id);

const scans = ref<ScanSummary[]>([]);
const drift = ref<DriftEvent[]>([]);
const regressions = ref<RegressionEvent[]>([]);
const latestReport = ref<ScanReport | null>(null);
const error = ref("");
const loading = ref(false);

onMounted(async () => {
  loading.value = true;
  try {
    [scans.value, drift.value, regressions.value] = await Promise.all([
      hsmScans(hsmID, 100),
      hsmDrift(hsmID, 25),
      hsmRegressions(hsmID, 25),
    ]);
    if (scans.value.length > 0) {
      const full = await hsmScan(hsmID, scans.value[0].id);
      latestReport.value = (full.report as ScanReport) ?? null;
    }
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
});

// Oldest → newest for the sparkline.
const scoreHistory = computed(() => scans.value.map((s) => s.score).reverse());
const latest = computed(() => scans.value[0]);
const token = computed(() => latestReport.value?.inventory.slot.token);

const certs = computed(() => {
  const objects = latestReport.value?.inventory.objects ?? [];
  return objects
    .filter((o) => o.class === "certificate" && o.certificate)
    .sort((a, b) =>
      (a.certificate?.not_after ?? "").localeCompare(b.certificate?.not_after ?? ""),
    );
});

function fmt(ts: string): string {
  return ts.replace("T", " ").slice(0, 19);
}

function signed(n: number): string {
  return n > 0 ? `+${n}` : String(n);
}

function scoreClass(score: number): string {
  if (score >= 90) return "good";
  if (score >= 70) return "warn";
  return "bad";
}
</script>

<template>
  <div v-if="error" class="error">{{ error }}</div>
  <p v-if="loading" class="muted">{{ t("detail.loading") }}</p>

  <template v-if="latest">
    <div class="card grid">
      <div class="stat">
        <div class="score" :class="scoreClass(latest.score)">
          {{ latest.score }}<span style="font-size: 1rem">/100</span>
        </div>
        <div class="label">{{ t("detail.latestScore", { date: fmt(latest.taken_at) }) }}</div>
      </div>
      <div>
        <div class="label" style="font-size: 0.72rem; text-transform: uppercase; color: var(--muted)">
          {{ t("detail.scoreHistory", { n: scans.length }) }}
        </div>
        <Sparkline :values="scoreHistory" />
      </div>
      <dl v-if="token">
        <dt style="font-size: 0.72rem; text-transform: uppercase; color: var(--muted)">{{ t("th.token") }}</dt>
        <dd style="font-weight: 500">{{ token.label }}</dd>
        <dt style="font-size: 0.72rem; text-transform: uppercase; color: var(--muted)">{{ t("detail.device") }}</dt>
        <dd>{{ token.manufacturer }} {{ token.model }} · fw {{ token.firmware_version }}</dd>
      </dl>
      <div class="stat">
        <div class="value">{{ latest.critical + latest.high + latest.medium + latest.low }}</div>
        <div class="label">{{ t("detail.findingsLatest") }}</div>
      </div>
    </div>

    <h2>{{ t("detail.regressions") }}</h2>
    <div v-if="regressions.length === 0" class="card muted">{{ t("detail.noRegressions") }}</div>
    <div v-for="e in regressions" :key="e.id" class="card">
      <strong>{{ fmt(e.detected_at) }}</strong>
      <span class="muted"> — {{ t("detail.regBetween", { delta: signed(e.score_delta), old: e.old_scan_id, new: e.new_scan_id }) }}</span>
      <ul style="margin: 0.5rem 0 0; padding-left: 1.25rem">
        <li v-for="(r, i) in e.detail.reasons" :key="'r' + i">{{ r }}</li>
      </ul>
    </div>

    <h2>{{ t("detail.driftEvents") }}</h2>
    <div v-if="drift.length === 0" class="card muted">{{ t("detail.noDrift") }}</div>
    <div v-for="e in drift" :key="e.id" class="card">
      <strong>{{ fmt(e.detected_at) }}</strong>
      <span class="muted"> — {{ t("detail.driftBetween", { n: e.changes, old: e.old_scan_id, new: e.new_scan_id }) }}</span>
      <ul style="margin: 0.5rem 0 0; padding-left: 1.25rem">
        <li v-for="(c, i) in e.diff.token_changes ?? []" :key="'t' + i">
          {{ c.field }} {{ t("detail.changed") }} <code>{{ c.old }}</code> → <code>{{ c.new }}</code>
        </li>
        <li v-for="(m, i) in e.diff.mechanisms_added ?? []" :key="'ma' + i">
          {{ t("detail.mechanism") }} <code>{{ m }}</code> {{ t("detail.nowAvailable") }}
        </li>
        <li v-for="(m, i) in e.diff.mechanisms_removed ?? []" :key="'mr' + i">
          {{ t("detail.mechanism") }} <code>{{ m }}</code> {{ t("detail.noLongerAvailable") }}
        </li>
        <li v-for="(o, i) in e.diff.objects_added ?? []" :key="'oa' + i">{{ o }} {{ t("detail.added") }}</li>
        <li v-for="(o, i) in e.diff.objects_removed ?? []" :key="'or' + i">{{ o }} {{ t("detail.removed") }}</li>
        <li v-for="(c, i) in e.diff.object_changes ?? []" :key="'oc' + i">
          {{ c.object }}: {{ c.field }} {{ t("detail.changed") }} <code>{{ c.old }}</code> → <code>{{ c.new }}</code>
        </li>
      </ul>
    </div>

    <h2>{{ t("detail.certsLatest") }}</h2>
    <div v-if="certs.length === 0" class="card muted">{{ t("detail.noCerts") }}</div>
    <div v-else class="card">
      <div class="tablebox">
        <table>
          <thead>
            <tr><th>{{ t("th.label") }}</th><th>{{ t("th.subject") }}</th><th>{{ t("th.expires") }}</th></tr>
          </thead>
          <tbody>
            <tr v-for="(o, i) in certs" :key="i">
              <td>{{ o.label }}</td>
              <td>{{ o.certificate?.subject }}</td>
              <td>{{ o.certificate?.not_after.slice(0, 10) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <h2>{{ t("detail.scanHistory") }}</h2>
    <div class="card">
      <div class="tablebox">
        <table>
          <thead>
            <tr>
              <th>{{ t("th.takenAt") }}</th>
              <th>{{ t("th.score") }}</th>
              <th>{{ t("th.critical") }}</th>
              <th>{{ t("th.high") }}</th>
              <th>{{ t("th.medium") }}</th>
              <th>{{ t("th.low") }}</th>
              <th>{{ t("th.objects") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in scans" :key="s.id">
              <td>{{ fmt(s.taken_at) }}</td>
              <td><strong>{{ s.score }}</strong></td>
              <td>{{ s.critical || "" }}</td>
              <td>{{ s.high || "" }}</td>
              <td>{{ s.medium || "" }}</td>
              <td>{{ s.low || "" }}</td>
              <td class="muted">
                {{ s.private_keys }}p / {{ s.public_keys }}pub / {{ s.secret_keys }}s / {{ s.certificates }}c
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </template>

  <div v-else-if="!loading" class="card muted">{{ t("detail.noScans") }}</div>
</template>
