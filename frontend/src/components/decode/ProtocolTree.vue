<template>
  <div class="protocol-tree">
    <el-tree
      :data="treeData"
      :props="{ children: 'children', label: 'label' }"
      default-expand-all
      highlight-current
    >
      <template #default="{ data }">
        <span class="tree-node">
          <span class="node-label">{{ data.label }}</span>
          <span v-if="data.value !== undefined" class="node-value">{{ data.value }}</span>
        </span>
      </template>
    </el-tree>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{ layers: any[] }>()

const treeData = computed(() => {
  return (props.layers || []).map(layer => layerToTree(layer))
})

function layerToTree(layer: any): any {
  const layerName = layer.layer || 'Unknown'
  const children: any[] = []

  for (const [key, value] of Object.entries(layer)) {
    if (key === 'layer') continue
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      children.push({
        label: key,
        children: Object.entries(value).map(([k, v]) => ({
          label: k,
          value: String(v),
        })),
      })
    } else if (Array.isArray(value)) {
      children.push({
        label: `${key} (${value.length})`,
        children: value.slice(0, 20).map((item, i) => ({
          label: typeof item === 'object' ? `[${i}]` : String(item),
          value: typeof item === 'object' ? JSON.stringify(item) : undefined,
        })),
      })
    } else {
      children.push({ label: key, value: String(value) })
    }
  }

  return { label: layerName, children }
}
</script>

<style scoped>
.protocol-tree {
  max-height: 400px;
  overflow-y: auto;
}
.tree-node {
  display: flex;
  gap: 8px;
  font-size: 13px;
}
.node-label {
  color: #606266;
}
.node-value {
  color: #409eff;
  font-family: monospace;
}
</style>
