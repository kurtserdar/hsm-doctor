<script setup lang="ts">
import { computed } from "vue";
import { t } from "../i18n";

// Renders a dependency-free SVG sparkline for values in the 0..100 range
// (health scores), oldest to newest.
const props = defineProps<{ values: number[] }>();

const W = 260;
const H = 48;
const PAD = 4;

const points = computed(() => {
  const v = props.values;
  if (v.length === 0) return "";
  if (v.length === 1) return `${PAD},${y(v[0])} ${W - PAD},${y(v[0])}`;
  const step = (W - 2 * PAD) / (v.length - 1);
  return v.map((s, i) => `${PAD + i * step},${y(s)}`).join(" ");
});

function y(score: number): number {
  const clamped = Math.max(0, Math.min(100, score));
  return PAD + (H - 2 * PAD) * (1 - clamped / 100);
}

const last = computed(() => props.values[props.values.length - 1] ?? 0);
const color = computed(() => {
  if (last.value >= 90) return "var(--good)";
  if (last.value >= 70) return "var(--warn)";
  return "var(--bad)";
});

const lastPoint = computed(() => {
  const parts = points.value.split(" ");
  return parts[parts.length - 1] ?? "";
});

// Area path: the line, then down to the baseline and back to the start.
const area = computed(() => {
  if (!points.value) return "";
  const pts = points.value.split(" ");
  const first = pts[0].split(",")[0];
  const lastX = pts[pts.length - 1].split(",")[0];
  const base = H - PAD;
  return `M${pts.map((p) => p).join(" L")} L${lastX},${base} L${first},${base} Z`;
});
</script>

<template>
  <svg
    :viewBox="`0 0 ${W} ${H}`"
    :width="W"
    :height="H"
    role="img"
    :aria-label="t('spark.aria')"
    preserveAspectRatio="none"
  >
    <path :d="area" :fill="color" fill-opacity="0.12" stroke="none" />
    <polyline
      :points="points"
      fill="none"
      :stroke="color"
      stroke-width="2"
      stroke-linejoin="round"
      stroke-linecap="round"
    />
    <circle
      v-if="lastPoint"
      :cx="lastPoint.split(',')[0]"
      :cy="lastPoint.split(',')[1]"
      r="3"
      :fill="color"
    />
  </svg>
</template>
