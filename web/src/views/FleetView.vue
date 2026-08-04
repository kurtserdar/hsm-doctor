<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { fleet, sharedKeys } from "../api";
import { t } from "../i18n";
import type { HSMSummary, SharedKey } from "../types";

const hsms = ref<HSMSummary[]>([]);
const shared = ref<SharedKey[]>([]);
const loading = ref(false);
const error = ref("");

onMounted(async () => {
  loading.value = true;
  try {
    [hsms.value, shared.value] = await Promise.all([fleet(), sharedKeys()]);
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
});

function shortFp(fp: string): string {
  return fp.length > 20 ? fp.slice(0, 20) + "…" : fp;
}

const scored = computed(() =>
  hsms.value.filter((h) => h.latest_score !== undefined) as (HSMSummary & { latest_score: number })[],
);
const needAttention = computed(() => scored.value.filter((h) => h.latest_score < 70).length);
const avgScore = computed(() =>
  scored.value.length
    ? Math.round(scored.value.reduce((n, h) => n + h.latest_score, 0) / scored.value.length)
    : null,
);

function scoreClass(score?: number): string {
  if (score === undefined) return "";
  if (score >= 90) return "ok";
  if (score >= 70) return "expiring";
  return "expired";
}

function avgClass(score: number | null): string {
  if (score === null) return "";
  if (score >= 90) return "good";
  if (score >= 70) return "warn";
  return "bad";
}

function ago(ts: string): string {
  const ms = Date.now() - new Date(ts).getTime();
  const min = Math.floor(ms / 60000);
  if (min < 1) return t("ago.justNow");
  if (min < 60) return t("ago.min", { n: min });
  const h = Math.floor(min / 60);
  if (h < 48) return t("ago.hour", { n: h });
  return t("ago.day", { n: Math.floor(h / 24) });
}
</script>

<template>
  <div v-if="error" class="error">{{ error }}</div>

  <div v-if="loading && !hsms.length" class="card">
    <div v-for="n in 4" :key="n" class="skeleton skel-line" style="width: 100%; height: 1.4rem; margin-bottom: 0.75rem"></div>
  </div>

  <div v-if="!loading && hsms.length === 0 && !error" class="card">
    <div class="empty">{{ t("fleet.empty") }}</div>
  </div>

  <template v-if="hsms.length">
    <div class="card grid">
      <div class="stat">
        <div class="value">{{ hsms.length }}</div>
        <div class="label">{{ t("fleet.totalHsms") }}</div>
      </div>
      <div class="stat">
        <div class="value" :style="{ color: needAttention ? 'var(--bad)' : 'var(--good)' }">
          {{ needAttention }}
        </div>
        <div class="label">{{ t("fleet.needAttention") }}</div>
      </div>
      <div class="stat" v-if="avgScore !== null">
        <div class="value" :class="avgClass(avgScore)">{{ avgScore }}</div>
        <div class="label">{{ t("fleet.avgScore") }}</div>
      </div>
    </div>

    <div v-if="shared.length" class="card">
      <h2 class="card-title">{{ t("shared.title") }}</h2>
      <p class="muted">{{ t("shared.subtitle") }}</p>
      <div v-for="k in shared" :key="k.fingerprint" class="finding">
        <span class="badge critical">{{ t("shared.onN", { n: k.hsm_count }) }}</span>
        <div>
          <div><code class="risk">{{ shortFp(k.fingerprint) }}</code> <span class="muted">{{ k.key_type }}</span></div>
          <div class="meta">
            <span v-for="(loc, i) in k.locations" :key="i">
              {{ loc.hsm_label || loc.serial }} · {{ loc.object }}<span v-if="i < k.locations.length - 1">, </span>
            </span>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="tablebox">
        <table>
          <thead>
            <tr>
              <th>{{ t("th.score") }}</th>
              <th>{{ t("th.token") }}</th>
              <th>{{ t("th.serial") }}</th>
              <th>{{ t("th.model") }}</th>
              <th>{{ t("th.firmware") }}</th>
              <th>{{ t("th.source") }}</th>
              <th>{{ t("th.lastSeen") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="h in hsms" :key="h.id">
              <td>
                <span v-if="h.latest_score !== undefined" class="badge" :class="scoreClass(h.latest_score)">
                  {{ h.latest_score }}/100
                </span>
                <span v-else class="muted">—</span>
              </td>
              <td>
                <RouterLink :to="`/fleet/${h.id}`">{{ h.label || t("token.unlabeled") }}</RouterLink>
              </td>
              <td><code>{{ h.serial }}</code></td>
              <td class="muted">{{ h.manufacturer }} {{ h.model }}</td>
              <td>{{ h.firmware }}</td>
              <td>{{ h.source }}</td>
              <td class="muted">{{ ago(h.last_seen) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </template>
</template>
