<template>
  <div class="analysis-view">
    <h2 class="page-title">Packet Analysis</h2>

    <div class="card-section">
      <PacketList
        :packets="packets"
        :total="totalPackets"
        :loading="loading"
        @select="onSelectPacket"
        @page-change="onPageChange"
      />
    </div>

    <el-row :gutter="16" v-if="currentPacket">
      <el-col :span="12">
        <div class="card-section">
          <h3>Protocol Decode</h3>
          <ProtocolTree :layers="currentPacket.decoded" />
        </div>
      </el-col>
      <el-col :span="12">
        <div class="card-section">
          <h3>Hex Dump</h3>
          <HexDump :content="currentPacket.hex_dump" />
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { onMounted, computed } from 'vue'
import { usePacketStore } from '../stores/packets'
import PacketList from '../components/decode/PacketList.vue'
import ProtocolTree from '../components/decode/ProtocolTree.vue'
import HexDump from '../components/decode/HexDump.vue'

const store = usePacketStore()
const packets = computed(() => store.packets)
const totalPackets = computed(() => store.totalPackets)
const loading = computed(() => store.loading)
const currentPacket = computed(() => store.currentPacket)

function onSelectPacket(packet: any) {
  store.fetchPacketDetail(packet.id)
}

function onPageChange(page: number) {
  if (store.currentPcapId) {
    store.fetchPackets(store.currentPcapId, page)
  }
}

onMounted(() => {
  if (store.currentPcapId) {
    store.fetchPackets(store.currentPcapId)
  }
})
</script>

<style scoped>
.analysis-view {
  height: calc(100vh - 100px);
  display: flex;
  flex-direction: column;
}
</style>
