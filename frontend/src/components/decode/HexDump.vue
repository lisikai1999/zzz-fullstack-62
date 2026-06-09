<template>
  <div class="hex-dump-container">
    <pre class="hex-dump">{{ content }}</pre>
  </div>
</template>

<script setup lang="ts">
defineProps<{ content: string }>()
</script>

<style scoped>
.hex-dump-container {
  max-height: 400px;
  overflow: auto;
}
</style>
