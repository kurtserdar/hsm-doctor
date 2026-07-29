<script setup lang="ts">
import { ref, watch } from "vue";
import { pqcAssess } from "../api";
import { store } from "../store";
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
</script>

<template>
  <div class="formrow">
    <label style="display: flex; align-items: center; gap: 0.4rem; margin: 0">
      <input v-model="withTest" type="checkbox" />
      functional probes (ephemeral objects)
    </label>
    <label style="display: flex; align-items: center; gap: 0.4rem; margin: 0">
      <input v-model="withHost" type="checkbox" />
      host OpenSSL check
    </label>
    <button class="primary" :disabled="loading || store.selectedSlot === null" @click="load">
      {{ loading ? "Assessing…" : "Assess" }}
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
            <tr><th>Family</th><th>Standard</th><th>Advertised</th><th>Mechanisms</th></tr>
          </thead>
          <tbody>
            <tr v-for="f in data.detection.families" :key="f.family">
              <td><strong>{{ f.family }}</strong> <span class="muted">({{ f.kind }})</span></td>
              <td class="muted">{{ f.fips }}</td>
              <td>
                <span v-if="f.advertised" class="badge ok">yes</span>
                <span v-else-if="f.incomplete" class="badge medium">partial</span>
                <span v-else class="muted">no</span>
              </td>
              <td class="muted">
                <code v-for="(m, i) in f.mechanisms ?? []" :key="i" style="margin-right: 0.3rem">{{ m }}</code>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p v-if="data.detection.vendor_defined?.length" class="muted" style="margin-bottom: 0; font-size: 0.85rem">
        Vendor-defined mechanisms advertised:
        <code v-for="(v, i) in data.detection.vendor_defined" :key="i" style="margin-right: 0.3rem">{{ v }}</code>
        — pre-standard PQC may hide here; consult vendor documentation.
      </p>
    </div>

    <div v-if="data.tests?.length" class="card">
      <h2 style="margin-top: 0; font-size: 1rem">Functional probes</h2>
      <div class="tablebox">
        <table>
          <thead><tr><th>Parameter set</th><th>Status</th><th>Detail</th></tr></thead>
          <tbody>
            <tr v-for="(t, i) in data.tests" :key="i">
              <td>{{ t.set }}</td>
              <td><span class="badge" :class="testBadge(t.status)">{{ t.status }}</span></td>
              <td class="muted">{{ t.detail }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="card grid">
      <div class="stat">
        <div class="value">{{ data.exposure.classical_private_keys }}/{{ data.exposure.total_private_keys }}</div>
        <div class="label">quantum-vulnerable private keys</div>
      </div>
      <div class="stat">
        <div class="value">{{ data.exposure.harvest_now_decrypt_later }}</div>
        <div class="label">HNDL-exposed (decrypt/unwrap)</div>
      </div>
      <div class="stat">
        <div class="value">{{ data.exposure.pqc_private_keys }}</div>
        <div class="label">post-quantum keys</div>
      </div>
      <div class="stat">
        <div class="value">{{ data.exposure.classical_certificates }}</div>
        <div class="label">classical certificates</div>
      </div>
    </div>

    <div v-if="data.host_openssl" class="card">
      <h2 style="margin-top: 0; font-size: 1rem">Host OpenSSL</h2>
      <p v-if="!data.host_openssl.available" class="muted" style="margin: 0">
        openssl is not available on the server host.
      </p>
      <p v-else style="margin: 0">
        <code>{{ data.host_openssl.version }}</code>
        <span class="muted">
          — ML-KEM: {{ data.host_openssl.ml_kem ? "yes" : "no" }},
          ML-DSA: {{ data.host_openssl.ml_dsa ? "yes" : "no" }},
          SLH-DSA: {{ data.host_openssl.slh_dsa ? "yes" : "no" }}
        </span>
      </p>
    </div>
  </template>
</template>
