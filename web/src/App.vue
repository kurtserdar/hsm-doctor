<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { setAuthToken } from "./api";
import { store } from "./store";

const route = useRoute();
const router = useRouter();
const title = computed(() => (route.meta.title as string) ?? "HSM Doctor");
const tokenInput = ref("");

function submitToken() {
  setAuthToken(tokenInput.value.trim());
  tokenInput.value = "";
  window.location.reload();
}

onMounted(async () => {
  await store.load();
  // Central mode has no local token pages; land on the fleet view.
  if (store.mode === "central" && route.path === "/") {
    void router.replace("/fleet");
  }
});
</script>

<template>
  <aside>
    <div class="brand">
      HSM Doctor
      <small>health · posture · diagnostics</small>
    </div>
    <nav>
      <template v-if="store.mode !== 'central'">
        <RouterLink to="/">Dashboard</RouterLink>
        <RouterLink to="/inventory">Inventory</RouterLink>
        <RouterLink to="/certificates">Certificates</RouterLink>
        <RouterLink to="/tests">Functional Tests</RouterLink>
        <RouterLink to="/bench">Performance</RouterLink>
        <RouterLink to="/pqc">PQC Readiness</RouterLink>
      </template>
      <RouterLink to="/fleet">Fleet</RouterLink>
    </nav>
  </aside>
  <main>
    <div class="topbar">
      <div>
        <h1>{{ title }}</h1>
        <div v-if="store.module" class="module">
          {{ store.module.description }} · {{ store.module.manufacturer }}
          {{ store.module.library_version }} · Cryptoki
          {{ store.module.cryptoki_version }}
        </div>
      </div>
      <div v-if="store.mode === 'local'">
        <label class="muted" style="font-size: 0.75rem; display: block">
          Token
        </label>
        <select v-model.number="store.selectedSlot">
          <option
            v-for="s in store.slots.filter((s) => s.token_present)"
            :key="s.id"
            :value="s.id"
          >
            {{ s.token?.label || "(unlabeled)" }} — slot {{ s.id }}
          </option>
        </select>
      </div>
    </div>
    <div v-if="store.error" class="error">{{ store.error }}</div>
    <div v-if="store.authRequired" class="card" style="max-width: 26rem">
      <h2 style="margin-top: 0; font-size: 1rem">API token required</h2>
      <p class="muted" style="font-size: 0.85rem">
        This server requires a bearer token. Paste a token from the server's
        auth configuration.
      </p>
      <form @submit.prevent="submitToken">
        <input
          v-model="tokenInput"
          type="password"
          placeholder="API token"
          style="width: 100%; margin-bottom: 0.75rem"
        />
        <button class="primary" type="submit">Connect</button>
      </form>
    </div>
    <RouterView v-if="!store.authRequired" />
  </main>
</template>
