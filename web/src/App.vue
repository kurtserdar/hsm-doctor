<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { setAuthToken } from "./api";
import { store } from "./store";
import { locale, setLocale, t } from "./i18n";
import type { Locale } from "./i18n";
import { setTheme, theme } from "./theme";
import type { Theme } from "./theme";

const route = useRoute();
const router = useRouter();
const title = computed(() => t((route.meta.title as string) ?? "nav.dashboard"));
const tokenInput = ref("");

const themes: Theme[] = ["auto", "light", "dark"];

function submitToken() {
  setAuthToken(tokenInput.value.trim());
  tokenInput.value = "";
  window.location.reload();
}

function onLocale(e: Event) {
  setLocale((e.target as HTMLSelectElement).value as Locale);
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
      <small>{{ t("brand.tagline") }}</small>
    </div>
    <nav>
      <template v-if="store.mode !== 'central'">
        <RouterLink to="/">{{ t("nav.dashboard") }}</RouterLink>
        <RouterLink to="/inventory">{{ t("nav.inventory") }}</RouterLink>
        <RouterLink to="/certificates">{{ t("nav.certificates") }}</RouterLink>
        <RouterLink to="/tests">{{ t("nav.tests") }}</RouterLink>
        <RouterLink to="/bench">{{ t("nav.bench") }}</RouterLink>
        <RouterLink to="/pqc">{{ t("nav.pqc") }}</RouterLink>
      </template>
      <RouterLink to="/fleet">{{ t("nav.fleet") }}</RouterLink>
    </nav>
    <div class="rail-foot">
      <div class="themetoggle" role="group" :aria-label="t('theme.label')">
        <button
          v-for="th in themes"
          :key="th"
          :class="{ on: theme === th }"
          @click="setTheme(th)"
        >
          {{ t("theme." + th) }}
        </button>
      </div>
      <label class="eyebrow" style="margin: 0">
        {{ t("lang.label") }}
        <select :value="locale" @change="onLocale" style="width: 100%; margin-top: var(--sp-1)">
          <option value="en">English</option>
          <option value="tr">Türkçe</option>
        </select>
      </label>
    </div>
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
        <label class="eyebrow" style="margin: 0">{{ t("topbar.token") }}</label>
        <select v-model.number="store.selectedSlot" style="margin-top: var(--sp-1)">
          <option
            v-for="s in store.slots.filter((s) => s.token_present)"
            :key="s.id"
            :value="s.id"
          >
            {{ s.token?.label || t("token.unlabeled") }} — {{ t("token.slot") }} {{ s.id }}
          </option>
        </select>
      </div>
    </div>
    <div v-if="store.error" class="error">{{ store.error }}</div>
    <div v-if="store.authRequired" class="card" style="max-width: 26rem">
      <h2 class="card-title">{{ t("auth.signin") }}</h2>
      <template v-if="store.oidc">
        <p class="muted">{{ t("auth.sso.note") }}</p>
        <a class="primary" href="/auth/login"
           style="display: inline-block; text-decoration: none; margin-bottom: var(--sp-4); padding: var(--sp-2) var(--sp-4); border-radius: var(--r-sm)">
          {{ t("auth.sso.button") }}
        </a>
        <details>
          <summary class="muted">{{ t("auth.useToken") }}</summary>
          <form @submit.prevent="submitToken" style="margin-top: var(--sp-3)">
            <input
              v-model="tokenInput"
              type="password"
              :placeholder="t('auth.token.placeholder')"
              style="width: 100%; margin-bottom: var(--sp-3)"
            />
            <button class="primary" type="submit">{{ t("auth.connect") }}</button>
          </form>
        </details>
      </template>
      <template v-else>
        <p class="muted">{{ t("auth.token.note") }}</p>
        <form @submit.prevent="submitToken">
          <input
            v-model="tokenInput"
            type="password"
            :placeholder="t('auth.token.placeholder')"
            style="width: 100%; margin-bottom: var(--sp-3)"
          />
          <button class="primary" type="submit">{{ t("auth.connect") }}</button>
        </form>
      </template>
    </div>
    <RouterView v-if="!store.authRequired" />
  </main>
</template>
