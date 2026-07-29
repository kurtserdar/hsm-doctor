import { createRouter, createWebHistory } from "vue-router";
import DashboardView from "./views/DashboardView.vue";
import InventoryView from "./views/InventoryView.vue";
import CertificatesView from "./views/CertificatesView.vue";
import TestsView from "./views/TestsView.vue";
import BenchView from "./views/BenchView.vue";
import FleetView from "./views/FleetView.vue";
import HSMDetailView from "./views/HSMDetailView.vue";

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/", name: "dashboard", component: DashboardView, meta: { title: "Dashboard" } },
    { path: "/fleet", name: "fleet", component: FleetView, meta: { title: "Fleet" } },
    { path: "/fleet/:id", name: "hsm-detail", component: HSMDetailView, meta: { title: "HSM History" } },
    { path: "/inventory", name: "inventory", component: InventoryView, meta: { title: "Inventory" } },
    { path: "/certificates", name: "certificates", component: CertificatesView, meta: { title: "Certificates" } },
    { path: "/tests", name: "tests", component: TestsView, meta: { title: "Functional Tests" } },
    { path: "/bench", name: "bench", component: BenchView, meta: { title: "Performance" } },
  ],
});
