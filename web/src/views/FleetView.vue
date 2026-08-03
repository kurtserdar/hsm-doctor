<script setup lang="ts">
import { onMounted, ref } from "vue";
import { fleet } from "../api";
import { t } from "../i18n";
import type { HSMSummary } from "../types";

const hsms = ref<HSMSummary[]>([]);
const loading = ref(false);
const error = ref("");

onMounted(async () => {
  loading.value = true;
  try {
    hsms.value = await fleet();
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
});

function scoreClass(score?: number): string {
  if (score === undefined) return "";
  if (score >= 90) return "ok";
  if (score >= 70) return "expiring";
  return "expired";
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
  <p v-if="loading" class="muted">{{ t("fleet.loading") }}</p>

  <div v-if="!loading && hsms.length === 0 && !error" class="card">
    {{ t("fleet.empty") }}
  </div>

  <div v-if="hsms.length" class="card">
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
