<template>
  <el-container class="app-container">
    <el-header class="app-header">
      <div class="header-left">
        <h1>Traffic Analyzer</h1>
      </div>
      <el-menu mode="horizontal" :router="true" :default-active="route.path" class="header-menu">
        <el-menu-item index="/">Upload</el-menu-item>
        <el-menu-item index="/analysis" :disabled="!currentPcapId">Analysis</el-menu-item>
        <el-menu-item index="/sessions" :disabled="!currentPcapId">Sessions</el-menu-item>
        <el-menu-item index="/sensitive" :disabled="!currentPcapId">Sensitive</el-menu-item>
        <el-menu-item index="/replay">Replay</el-menu-item>
      </el-menu>
    </el-header>
    <el-main>
      <router-view />
    </el-main>
  </el-container>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { usePacketStore } from './stores/packets'

const route = useRoute()
const packetStore = usePacketStore()
const currentPcapId = computed(() => packetStore.currentPcapId)
</script>

<style scoped>
.app-container {
  height: 100vh;
}
.app-header {
  display: flex;
  align-items: center;
  border-bottom: 1px solid #e4e7ed;
  padding: 0 20px;
}
.header-left h1 {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: #303133;
  margin-right: 40px;
}
.header-menu {
  border-bottom: none;
}
</style>
