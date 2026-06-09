<template>
  <div class="replay-panel">
    <el-form label-position="top" size="small">
      <el-form-item label="Session ID">
        <el-input-number v-model="config.sessionId" :min="1" style="width: 100%" />
      </el-form-item>
      <el-form-item label="Target IP">
        <el-input v-model="config.targetIp" placeholder="192.168.1.100" />
      </el-form-item>
      <el-form-item label="Target Port">
        <el-input-number v-model="config.targetPort" :min="1" :max="65535" style="width: 100%" />
      </el-form-item>
      <el-form-item label="Speed Factor">
        <el-slider v-model="config.speedFactor" :min="0.1" :max="10" :step="0.1" show-input />
      </el-form-item>
      <el-form-item label="Host Header Override">
        <el-input v-model="hostOverride" placeholder="Leave empty to keep original" />
      </el-form-item>
      <el-form-item>
        <el-button v-if="!running" type="primary" @click="start" :disabled="!isValid" style="width: 100%">
          Start Replay
        </el-button>
        <el-button v-else type="danger" @click="$emit('stop')" style="width: 100%">
          Stop Replay
        </el-button>
      </el-form-item>
    </el-form>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, computed } from 'vue'

defineProps<{ running: boolean }>()
const emit = defineEmits<{
  start: [config: any]
  stop: []
}>()

const config = reactive({
  sessionId: 1,
  targetIp: '',
  targetPort: 80,
  speedFactor: 1.0,
})

const hostOverride = ref('')

const isValid = computed(() => config.targetIp && config.targetPort > 0 && config.sessionId > 0)

function start() {
  const overrides = hostOverride.value ? { host_header: hostOverride.value } : null
  emit('start', { ...config, fieldOverrides: overrides })
}
</script>
