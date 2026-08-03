<script setup lang="ts">
import { ref, watch } from "vue";
import { pqcAssess } from "../api";
import { store } from "../store";
import { t } from "../i18n";
import type { PQCResponse } from "../types";

const data = ref<PQCResponse | null>(null);
const withTest = ref(false);
const withHost = ref(true);
const loading = ref(false);
const error = ref("");

async function load() {
  if (store.selectedSlot === null) return;
  loading.value = true;
  error.value = "";
  try {
    data.value = await pqcAssess(store.selectedSlot, {
      test: withTest.value,
      host: withHost.value,
    });
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    loading.value = false;
  }
}

watch(() => store.selectedSlot, load, { immediate: true });

function verdictClass(v: string): string {
  if (v === "READY") return "ok";
  if (v === "PARTIAL") return "medium";
  return "expired";
}

function testBadge(status: string): string {
  if (status === "PASS") return "pass";
  if (status === "FAIL") return "fail";
  return "skip";
}

function yn(v: boolean): string {
  return v ? t("pqc.yes") : t("pqc.no");
}
</script>

<template>
  <div class="formrow">
    <label style="display: flex; align-items: center; gap: 0.4rem; margin: 0">
      <input v-model="withTest" type="checkbox" />
      {{ t("pqc.probes") }}
    </label>
    <label style="display: flex; align-items: center; gap: 0.4rem; margin: 0">
      <input v-model="withHost" type="checkbox" />
      {{ t("pqc.hostCheck") }}
    </label>
    <button class="primary" :disabled="loading || store.selectedSlot === null" @click="load">
      {{ loading ? t("pqc.assessing") : t("pqc.assess") }}
    </button>
  </div>

  <div v-if="error" class="error">{{ error }}</div>

  <template v-if="data">
    <div class="card">
      <span class="badge" :class="verdictClass(data.detection.verdict)" style="font-size: 0.9rem">
        {{ data.detection.verdict }}
      </span>
      <span v-if="data.detection.cryptoki_version" class="muted">
        · Cryptoki {{ data.detection.cryptoki_version }}
      </span>
      <p class="muted" style="margin-bottom: 0">{{ data.exposure.summary }}</p>
    </div>

    <div class="card">
      <div class="tablebox">
        <table>
          <thead>
            <tr><th>{{ t("th.family") }}</th><th>{{ t("th.standard") }}</th><th>{{ t("th.advertised") }}</th><th>{{ t("th.mechanisms") }}</th></tr>
          </thead>
          <tbody>
            <tr v-for="f in data.detection.families" :key="f.family">
              <td><strong>{{ f.family }}</strong> <span class="muted">({{ f.kind }})</span></td>
              <td class="muted">{{ f.fips }}</td>
              <td>
                <span v-if="f.advertised" class="badge ok">{{ t("pqc.yes") }}</span>
                <span v-else-if="f.incomplete" class="badge medium">{{ t("pqc.partial") }}</span>
                <span v-else class="muted">{{ t("pqc.no") }}</span>
              </td>
              <td class="muted">
                <code v-for="(m, i) in f.mechanisms ?? []" :key="i" style="margin-right: 0.3rem">{{ m }}</code>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="data.detection.vendor_defined?.length" class="muted" style="margin-bottom: 0; font-size: 0.85rem">
        {{ t("pqc.vendorDefined") }}
        <code v-for="(v, i) in data.detection.vendor_defined" :key="i" style="margin-right: 0.3rem">{{ v }}</code>
        {{ t("pqc.vendorHint") }}
      </p>
    </div>

    <div v-if="data.tests?.length" class="card">
      <h2 style="margin-top: 0; font-size: 1rem">{{ t("pqc.probesTitle") }}</h2>
      <div class="tablebox">
        <table>
          <thead><tr><th>{{ t("th.paramSet") }}</th><th>{{ t("th.status") }}</th><th>{{ t("th.detail") }}</th></tr></thead>
          <tbody>
            <tr v-for="(probe, i) in data.tests" :key="i">
              <td>{{ probe.set }}</td>
              <td><span class="badge" :class="testBadge(probe.status)">{{ probe.status }}</span></td>
              <td class="muted">{{ probe.detail }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card grid">
      <div class="stat">
        <div class="value">{{ data.exposure.classical_private_keys }}/{{ data.exposure.total_private_keys }}</div>
        <div class="label">{{ t("pqc.qvKeys") }}</div>
      </div>
      <div class="stat">
        <div class="value">{{ data.exposure.harvest_now_decrypt_later }}</div>
        <div class="label">{{ t("pqc.hndl") }}</div>
      </div>
      <div class="stat">
        <div class="value">{{ data.exposure.pqc_private_keys }}</div>
        <div class="label">{{ t("pqc.pqKeys") }}</div>
      </div>
      <div class="stat">
        <div class="value">{{ data.exposure.classical_certificates }}</div>
        <div class="label">{{ t("pqc.classicalCerts") }}</div>
      </div>
    </div>

    <div v-if="data.host_openssl" class="card">
      <h2 style="margin-top: 0; font-size: 1rem">{{ t("pqc.hostTitle") }}</h2>
      <p v-if="!data.host_openssl.available" class="muted" style="margin: 0">
        {{ t("pqc.noOpenssl") }}
      </p>
      <p v-else style="margin: 0">
        <code>{{ data.host_openssl.version }}</code>
        <span class="muted">
          — {{ t("pqc.opensslLine", { mlkem: yn(data.host_openssl.ml_kem), mldsa: yn(data.host_openssl.ml_dsa), slhdsa: yn(data.host_openssl.slh_dsa) }) }}
        </span>
      </p>
    </div>
  </template>
</template>
