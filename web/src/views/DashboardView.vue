<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { scan } from "../api";
import { store } from "../store";
import { t } from "../i18n";
import type { ScanReport, Severity } from "../types";

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

const severities: Severity[] = ["critical", "high", "medium", "low"];

const sevCounts = computed(() => {
  const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of report.value?.findings ?? []) {
    if (c[f.severity] !== undefined) c[f.severity]++;
  }
  return c;
});

const totalFindings = computed(() =>
  severities.reduce((n, s) => n + sevCounts.value[s], 0),
);
</script>

<template>
  <div v-if="error" class="error">{{ error }}</div>

  <div v-if="loading && !report" class="card grid">
    <div v-for="n in 6" :key="n" class="stat">
      <div class="skeleton skel-line" style="width: 60%; height: 1.8rem"></div>
      <div class="skeleton skel-line" style="width: 80%"></div>
    </div>
  </div>

  <template v-if="report">
    <div class="card grid">
      <div class="stat">
        <div class="score" :class="scoreClass(report.score)">
          {{ report.score }}<span style="font-size: var(--fs-md)">/100</span>
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
      <h2 class="card-title">
        {{ t("dash.vendor", { provider: report.vendor.provider }) }}
        <span v-if="report.vendor.experimental" class="badge medium">
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
      <h2 class="card-title">
        {{ t("dash.findingsTitle") }}
        <span v-if="report.rule_packs?.length" class="muted" style="font-weight: 400; font-size: var(--fs-sm)">
          — {{ t("dash.rulePacks", { packs: report.rule_packs.join(", ") }) }}
        </span>
      </h2>

      <p v-if="!totalFindings" class="muted">{{ t("dash.noFindings") }}</p>

      <template v-else>
        <div class="sevbar" :aria-label="t('dash.findingsTitle')">
          <span
            v-for="s in severities.filter((s) => sevCounts[s] > 0)"
            :key="s"
            :class="s"
            :style="{ width: (sevCounts[s] / totalFindings) * 100 + '%' }"
          ></span>
        </div>
        <div class="sevlegend">
          <span v-for="s in severities.filter((s) => sevCounts[s] > 0)" :key="s">
            <span class="dot" :style="{ background: 'var(--' + s + ')' }"></span>
            {{ t("th." + s) }} {{ sevCounts[s] }}
          </span>
        </div>

        <div class="findings" style="margin-top: var(--sp-4)">
          <div v-for="(f, i) in report.findings" :key="i" class="finding" :class="f.severity">
            <span class="badge" :class="f.severity">{{ f.severity }}</span>
            <div>
              <div class="f-head">
                <code>{{ f.rule_id }}</code>
                <span class="f-title">{{ f.title }}</span>
              </div>
              <div v-if="f.object || f.detail" class="f-meta">
                {{ f.object }}<template v-if="f.detail"> — {{ f.detail }}</template>
              </div>
              <div v-if="f.remediation" class="f-fix">{{ t("common.fix") }}: {{ f.remediation }}</div>
            </div>
          </div>
        </div>
      </template>
    </div>
  </template>
</template>
