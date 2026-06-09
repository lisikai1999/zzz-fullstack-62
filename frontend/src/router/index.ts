import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/', name: 'upload', component: () => import('../views/UploadView.vue') },
  { path: '/analysis', name: 'analysis', component: () => import('../views/AnalysisView.vue') },
  { path: '/sessions', name: 'sessions', component: () => import('../views/SessionsView.vue') },
  { path: '/sensitive', name: 'sensitive', component: () => import('../views/SensitiveView.vue') },
  { path: '/replay', name: 'replay', component: () => import('../views/ReplayView.vue') },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
