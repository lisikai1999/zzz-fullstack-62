<template>
  <div class="upload-view">
    <h2 class="page-title">Upload PCAP File</h2>

    <div class="card-section">
      <el-upload
        drag
        :auto-upload="false"
        :on-change="handleFileChange"
        accept=".pcap,.cap"
        :show-file-list="false"
      >
        <el-icon :size="60"><Upload /></el-icon>
        <div class="el-upload__text">Drop pcap file here or <em>click to select</em></div>
      </el-upload>

      <div v-if="selectedFile" class="file-info">
        <p>File: {{ selectedFile.name }} ({{ formatSize(selectedFile.size) }})</p>
        <el-button type="primary" @click="doUpload" :loading="uploading">
          Upload & Analyze
        </el-button>
      </div>

      <div v-if="parseStatus" class="parse-status">
        <el-alert :type="statusType" :closable="false">
          <template #title>
            Status: {{ parseStatus }}
            <span v-if="parseStatus === 'parsing'"> ... analyzing packets</span>
            <span v-if="parseStatus === 'completed'"> ({{ packetCount }} packets)</span>
          </template>
        </el-alert>
        <el-button v-if="parseStatus === 'completed'" type="success" @click="goToAnalysis" style="margin-top: 12px">
          View Analysis
        </el-button>
      </div>
    </div>

    <div class="card-section" v-if="pcapList.length">
      <h3>Previous Uploads</h3>
      <el-table :data="pcapList" style="width: 100%; margin-top: 12px">
        <el-table-column prop="filename" label="Filename" />
        <el-table-column prop="file_size" label="Size" :formatter="(r: any) => formatSize(r.file_size)" width="100" />
        <el-table-column prop="packet_count" label="Packets" width="100" />
        <el-table-column prop="parse_status" label="Status" width="120">
          <template #default="{ row }">
            <el-tag :type="row.parse_status === 'completed' ? 'success' : row.parse_status === 'error' ? 'danger' : 'warning'" size="small">
              {{ row.parse_status }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Actions" width="120">
          <template #default="{ row }">
            <el-button size="small" @click="selectPcap(row)" :disabled="row.parse_status !== 'completed'">Open</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { Upload } from '@element-plus/icons-vue'
import { usePacketStore } from '../stores/packets'

const router = useRouter()
const store = usePacketStore()

const selectedFile = ref<File | null>(null)
const uploading = ref(false)
const parseStatus = ref<string | null>(null)
const packetCount = ref(0)
const pcapList = computed(() => store.pcapList)

const statusType = computed(() => {
  if (parseStatus.value === 'completed') return 'success'
  if (parseStatus.value === 'error') return 'error'
  return 'info'
})

function handleFileChange(uploadFile: any) {
  selectedFile.value = uploadFile.raw
}

async function doUpload() {
  if (!selectedFile.value) return
  uploading.value = true
  parseStatus.value = 'uploading'

  try {
    const result = await store.uploadPcap(selectedFile.value)
    parseStatus.value = 'parsing'
    pollStatus(result.id)
  } catch (e: any) {
    parseStatus.value = 'error'
  } finally {
    uploading.value = false
  }
}

async function pollStatus(pcapId: number) {
  const interval = setInterval(async () => {
    const status = await store.checkStatus(pcapId)
    parseStatus.value = status.parse_status
    packetCount.value = status.packet_count
    if (status.parse_status === 'completed' || status.parse_status === 'error') {
      clearInterval(interval)
      store.fetchPcapList()
    }
  }, 1000)
}

function goToAnalysis() {
  router.push('/analysis')
}

function selectPcap(row: any) {
  store.currentPcapId = row.id
  router.push('/analysis')
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / 1048576).toFixed(1) + ' MB'
}

onMounted(() => {
  store.fetchPcapList()
})
</script>

<style scoped>
.upload-view {
  max-width: 900px;
  margin: 0 auto;
}
.file-info {
  margin-top: 16px;
  display: flex;
  align-items: center;
  gap: 16px;
}
.parse-status {
  margin-top: 16px;
}
</style>
