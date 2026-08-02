<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { hsmDrift, hsmRegressions, hsmScan, hsmScans } from "../api";
import Sparkline from "../components/Sparkline.vue";
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

function scoreClass(score: number): string {
  if (score >= 90) return "good";
  if (score >= 70) return "warn";
  return "bad";
}
</script>

<template>
  <div v-if="error" class="error">{{ error }}</div>
  <p v-if="loading" class="muted">Loading history…</p>

  <template v-if="latest">
    <div class="card grid">
      <div class="stat">
        <div class="score" :class="scoreClass(latest.score)">
          {{ latest.score }}<span style="font-size: 1rem">/100</span>
        </div>
        <div class="label">latest score · {{ fmt(latest.taken_at) }}</div>
      </div>
      <div>
        <div class="label" style="font-size: 0.72rem; text-transform: uppercase; color: var(--muted)">
          score history ({{ scans.length }} scans)
        </div>
        <Sparkline :values="scoreHistory" />
      </div>
      <dl v-if="token">
        <dt style="font-size: 0.72rem; text-transform: uppercase; color: var(--muted)">Token</dt>
        <dd style="font-weight: 500">{{ token.label }}</dd>
        <dt style="font-size: 0.72rem; text-transform: uppercase; color: var(--muted)">Device</dt>
        <dd>{{ token.manufacturer }} {{ token.model }} · fw {{ token.firmware_version }}</dd>
      </dl>
      <div class="stat">
        <div class="value">{{ latest.critical + latest.high + latest.medium + latest.low }}</div>
        <div class="label">findings in latest scan</div>
      </div>
    </div>

    <h2>Posture regressions</h2>
    <div v-if="regressions.length === 0" class="card muted">No posture regressions recorded.</div>
    <div v-for="e in regressions" :key="e.id" class="card">
      <strong>{{ fmt(e.detected_at) }}</strong>
      <span class="muted"> — score {{ e.score_delta > 0 ? "+" : "" }}{{ e.score_delta }} between scan #{{ e.old_scan_id }} and #{{ e.new_scan_id }}</span>
      <ul style="margin: 0.5rem 0 0; padding-left: 1.25rem">
        <li v-for="(r, i) in e.detail.reasons" :key="'r' + i">{{ r }}</li>
      </ul>
    </div>

    <h2>Drift events</h2>
    <div v-if="drift.length === 0" class="card muted">No drift recorded.</div>
    <div v-for="e in drift" :key="e.id" class="card">
      <strong>{{ fmt(e.detected_at) }}</strong>
      <span class="muted"> — {{ e.changes }} change(s) between scan #{{ e.old_scan_id }} and #{{ e.new_scan_id }}</span>
      <ul style="margin: 0.5rem 0 0; padding-left: 1.25rem">
        <li v-for="(c, i) in e.diff.token_changes ?? []" :key="'t' + i">
          {{ c.field }} changed <code>{{ c.old }}</code> → <code>{{ c.new }}</code>
        </li>
        <li v-for="(m, i) in e.diff.mechanisms_added ?? []" :key="'ma' + i">
          mechanism <code>{{ m }}</code> now available
        </li>
        <li v-for="(m, i) in e.diff.mechanisms_removed ?? []" :key="'mr' + i">
          mechanism <code>{{ m }}</code> no longer available
        </li>
        <li v-for="(o, i) in e.diff.objects_added ?? []" :key="'oa' + i">{{ o }} added</li>
        <li v-for="(o, i) in e.diff.objects_removed ?? []" :key="'or' + i">{{ o }} removed</li>
        <li v-for="(c, i) in e.diff.object_changes ?? []" :key="'oc' + i">
          {{ c.object }}: {{ c.field }} changed <code>{{ c.old }}</code> → <code>{{ c.new }}</code>
        </li>
      </ul>
    </div>

    <h2>Certificates (latest scan)</h2>
    <div v-if="certs.length === 0" class="card muted">No certificates on this token.</div>
    <div v-else class="card">
      <div class="tablebox">
        <table>
          <thead>
            <tr><th>Label</th><th>Subject</th><th>Expires</th></tr>
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

    <h2>Scan history</h2>
    <div class="card">
      <div class="tablebox">
        <table>
          <thead>
            <tr>
              <th>Taken at</th>
              <th>Score</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
              <th>Objects</th>
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

  <div v-else-if="!loading" class="card muted">No scans recorded for this HSM yet.</div>
</template>
