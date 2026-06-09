<template>
  <div class="response-diff">
    <div v-if="diff.match" class="match-indicator">
      <el-tag type="success">Responses Match</el-tag>
    </div>
    <div v-else>
      <div class="diff-meta">
        <span>Original: {{ diff.original_length }}B</span>
        <span>Replayed: {{ diff.actual_length }}B</span>
        <span>Similarity: {{ diff.similarity_percent }}%</span>
      </div>
      <pre v-if="diff.diff_text" class="diff-content">{{ diff.diff_text }}</pre>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{ diff: any }>()
</script>

<style scoped>
.response-diff {
  font-size: 13px;
}
.diff-meta {
  display: flex;
  gap: 16px;
  margin-bottom: 8px;
  color: #606266;
}
.diff-content {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 12px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 12px;
  white-space: pre-wrap;
  max-height: 300px;
  overflow-y: auto;
}
</style>
