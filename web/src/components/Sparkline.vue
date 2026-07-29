<script setup lang="ts">
import { computed } from "vue";

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
</script>

<template>
  <svg
    :viewBox="`0 0 ${W} ${H}`"
    :width="W"
    :height="H"
    role="img"
    aria-label="Health score history"
  >
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
