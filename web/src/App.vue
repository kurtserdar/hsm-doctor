<script setup lang="ts">
import { computed, onMounted } from "vue";
import { useRoute } from "vue-router";
import { store } from "./store";

const route = useRoute();
const title = computed(() => (route.meta.title as string) ?? "HSM Doctor");

onMounted(() => {
  void store.load();
});
</script>

<template>
  <aside>
    <div class="brand">
      HSM Doctor
      <small>health · posture · diagnostics</small>
    </div>
    <nav>
      <RouterLink to="/">Dashboard</RouterLink>
      <RouterLink to="/inventory">Inventory</RouterLink>
      <RouterLink to="/certificates">Certificates</RouterLink>
      <RouterLink to="/tests">Functional Tests</RouterLink>
      <RouterLink to="/bench">Performance</RouterLink>
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
      <div>
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
    <RouterView />
  </main>
</template>
