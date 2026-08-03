import { createRouter, createWebHistory } from "vue-router";
import DashboardView from "./views/DashboardView.vue";
import InventoryView from "./views/InventoryView.vue";
import CertificatesView from "./views/CertificatesView.vue";
import TestsView from "./views/TestsView.vue";
import BenchView from "./views/BenchView.vue";
import FleetView from "./views/FleetView.vue";
import HSMDetailView from "./views/HSMDetailView.vue";
import PQCView from "./views/PQCView.vue";

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", name: "dashboard", component: DashboardView, meta: { title: "nav.dashboard" } },
    { path: "/fleet", name: "fleet", component: FleetView, meta: { title: "nav.fleet" } },
    { path: "/fleet/:id", name: "hsm-detail", component: HSMDetailView, meta: { title: "route.hsmHistory" } },
    { path: "/inventory", name: "inventory", component: InventoryView, meta: { title: "nav.inventory" } },
    { path: "/certificates", name: "certificates", component: CertificatesView, meta: { title: "nav.certificates" } },
    { path: "/tests", name: "tests", component: TestsView, meta: { title: "nav.tests" } },
    { path: "/bench", name: "bench", component: BenchView, meta: { title: "nav.bench" } },
    { path: "/pqc", name: "pqc", component: PQCView, meta: { title: "nav.pqc" } },
  ],
});
