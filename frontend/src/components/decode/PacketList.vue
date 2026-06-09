<template>
  <div class="packet-list">
    <el-table
      :data="packets"
      highlight-current-row
      @current-change="onSelect"
      size="small"
      :max-height="350"
      v-loading="loading"
      stripe
    >
      <el-table-column prop="packet_index" label="#" width="60" />
      <el-table-column prop="timestamp" label="Time" width="130">
        <template #default="{ row }">{{ formatTime(row.timestamp) }}</template>
      </el-table-column>
      <el-table-column prop="ip_src" label="Source" width="130" />
      <el-table-column prop="ip_dst" label="Destination" width="130" />
      <el-table-column prop="protocol_summary" label="Info" />
      <el-table-column prop="payload_length" label="Len" width="60" />
    </el-table>

    <el-pagination
      v-if="total > 50"
      layout="prev, pager, next"
      :total="total"
      :page-size="50"
      @current-change="$emit('page-change', $event)"
      style="margin-top: 12px; justify-content: center;"
    />
  </div>
</template>

<script setup lang="ts">
defineProps<{
  packets: any[]
  total: number
  loading: boolean
}>()

const emit = defineEmits<{
  select: [packet: any]
  'page-change': [page: number]
}>()

function onSelect(row: any) {
  if (row) emit('select', row)
}

function formatTime(ts: number): string {
  const d = new Date(ts * 1000)
  return d.toISOString().slice(11, 23)
}
</script>
