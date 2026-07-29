<script setup lang="ts">
import { ref, watch } from "vue";
import { certs } from "../api";
import { store } from "../store";
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
  if (status === "expired") return `expired ${-daysLeft} days ago`;
  if (status === "expiring") return `${daysLeft} days left`;
  return "ok";
}
</script>

<template>
  <div v-if="error" class="error">{{ error }}</div>

  <div class="formrow">
    <div>
      <label>Warn window (days)</label>
      <input v-model.number="warnDays" type="number" min="0" style="width: 6rem" />
    </div>
    <button class="primary" :disabled="loading" @click="load">Refresh</button>
  </div>

  <template v-if="data">
    <div class="card grid">
      <div class="stat">
        <div class="value">{{ data.counts.ok }}</div>
        <div class="label">ok</div>
      </div>
      <div class="stat">
        <div class="value">{{ data.counts.expiring }}</div>
        <div class="label">expiring ≤ {{ data.warn_days }}d</div>
      </div>
      <div class="stat">
        <div class="value">{{ data.counts.expired }}</div>
        <div class="label">expired</div>
      </div>
    </div>

    <div class="card">
      <p v-if="!(data.certificates ?? []).length" class="muted">
        No certificates found on the token.
      </p>
      <div v-else class="tablebox">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Label</th>
              <th>Subject</th>
              <th>Issuer</th>
              <th>Expires</th>
              <th>CA</th>
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
              <td>{{ c.is_ca ? "yes" : "" }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </template>
</template>
