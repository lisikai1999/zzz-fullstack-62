<template>
  <div ref="graphContainer" class="session-graph"></div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch, onBeforeUnmount } from 'vue'
import cytoscape from 'cytoscape'

const props = defineProps<{
  graph: { nodes: any[]; edges: any[] }
}>()

const emit = defineEmits<{
  'select-session': [session: any]
}>()

const graphContainer = ref<HTMLElement>()
let cy: any = null

function renderGraph() {
  if (!graphContainer.value || !props.graph.nodes.length) return

  if (cy) cy.destroy()

  const elements: any[] = []

  for (const node of props.graph.nodes) {
    elements.push({
      data: { id: node.id, label: node.label, size: Math.max(30, Math.min(80, node.packet_count / 2)) },
    })
  }

  for (const edge of props.graph.edges) {
    elements.push({
      data: {
        id: `e-${edge.session_id}`,
        source: edge.source,
        target: edge.target,
        label: edge.app_protocol || edge.protocol,
        sessionId: edge.session_id,
      },
    })
  }

  cy = cytoscape({
    container: graphContainer.value,
    elements,
    style: [
      {
        selector: 'node',
        style: {
          'background-color': '#409eff',
          label: 'data(label)',
          'font-size': '10px',
          'text-valign': 'bottom',
          'text-margin-y': 5,
          width: 'data(size)',
          height: 'data(size)',
        },
      },
      {
        selector: 'edge',
        style: {
          width: 2,
          'line-color': '#c0c4cc',
          'target-arrow-color': '#c0c4cc',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          label: 'data(label)',
          'font-size': '9px',
          'text-rotation': 'autorotate',
        },
      },
      {
        selector: ':selected',
        style: {
          'background-color': '#e6a23c',
          'line-color': '#e6a23c',
          'target-arrow-color': '#e6a23c',
        },
      },
    ],
    layout: { name: 'cose', animate: false },
  })

  cy.on('tap', 'edge', (evt: any) => {
    const sessionId = evt.target.data('sessionId')
    emit('select-session', { id: sessionId })
  })
}

watch(() => props.graph, renderGraph, { deep: true })
onMounted(renderGraph)
onBeforeUnmount(() => { if (cy) cy.destroy() })
</script>

<style scoped>
.session-graph {
  width: 100%;
  height: 440px;
}
</style>
