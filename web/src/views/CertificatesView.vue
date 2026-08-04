<script setup lang="ts">
import { ref, watch } from "vue";
import { certs } from "../api";
import { store } from "../store";
import { t } from "../i18n";
import type { CertsResponse } from "../types";

const data = ref<CertsResponse | null>(null);
const warnDays = ref(30);
const loading = ref(false);
const error = ref("");

async function load() {
  if (store.selectedSlot === null) return;
  loading.value = true;
  error.value = "";
  try {
    data.value = await certs(store.selectedSlot, warnDays.value);
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

watch(() => store.selectedSlot, load, { immediate: true });

function statusText(status: string, daysLeft: number): string {
  if (status === "expired") return t("cert.status.expired", { days: -daysLeft });
  if (status === "expiring") return t("cert.status.expiring", { days: daysLeft });
  return t("cert.status.ok");
}
</script>

<template>
  <div v-if="error" class="error">{{ error }}</div>

  <div class="formrow">
    <div>
      <label>{{ t("cert.warnWindow") }}</label>
      <input v-model.number="warnDays" type="number" min="0" style="width: 6rem" />
    </div>
    <button class="primary" :disabled="loading" @click="load">{{ t("common.refresh") }}</button>
  </div>

  <div v-if="loading && !data" class="card">
    <div v-for="n in 4" :key="n" class="skeleton skel-line" style="width: 100%; height: 1.3rem; margin-bottom: 0.6rem"></div>
  </div>

  <template v-if="data">
    <div class="card grid">
      <div class="stat">
        <div class="value">{{ data.counts.ok }}</div>
        <div class="label">{{ t("cert.ok") }}</div>
      </div>
      <div class="stat">
        <div class="value">{{ data.counts.expiring }}</div>
        <div class="label">{{ t("cert.expiringLe", { days: data.warn_days }) }}</div>
      </div>
      <div class="stat">
        <div class="value">{{ data.counts.expired }}</div>
        <div class="label">{{ t("cert.expired") }}</div>
      </div>
    </div>

    <div class="card">
      <div v-if="!(data.certificates ?? []).length" class="empty">
        {{ t("cert.none") }}
      </div>
      <div v-else class="tablebox">
        <table>
          <thead>
            <tr>
              <th>{{ t("th.status") }}</th>
              <th>{{ t("th.label") }}</th>
              <th>{{ t("th.subject") }}</th>
              <th>{{ t("th.issuer") }}</th>
              <th>{{ t("th.expires") }}</th>
              <th>{{ t("th.ca") }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(c, i) in data.certificates" :key="i">
              <td>
                <span class="badge" :class="c.status">
                  {{ statusText(c.status, c.days_left) }}
                </span>
              </td>
              <td>{{ c.label }}</td>
              <td>{{ c.subject }}</td>
              <td class="muted">{{ c.issuer }}</td>
              <td>{{ c.not_after.slice(0, 10) }}</td>
              <td>{{ c.is_ca ? t("cert.yes") : "" }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </template>
</template>
