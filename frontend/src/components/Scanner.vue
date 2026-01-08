<template>
  <div class="scanner-container">
    <a-layout style="height: 100vh">
      <a-layout-sider width="350" theme="light" style="border-right: 1px solid #f0f0f0">
        <div class="logo">SAST Scanner</div>
        <div class="vuln-list">
          <a-empty v-if="vulnerabilities.length === 0" description="No vulnerabilities found" />
          <div
            v-for="(vuln, index) in vulnerabilities"
            :key="index"
            class="vuln-item"
            :class="{ active: selectedVulnIndex === index }"
            @click="selectVuln(index)"
          >
            <div class="vuln-header">
              <a-tag :color="getSeverityColor(vuln.Severity)">{{ vuln.Severity }}</a-tag>
              <span class="vuln-type">{{ vuln.Type }}</span>
            </div>
            <div class="vuln-loc">Line: {{ vuln.Line }}</div>
            
            <div v-if="selectedVulnIndex === index" class="vuln-steps">
              <div 
                v-for="(step, sIndex) in vuln.Path" 
                :key="sIndex" 
                class="step-item"
                @click.stop="highlightLine(step.Line)"
              >
                <div class="step-label">
                  <span v-if="sIndex === 0">Source</span>
                  <span v-else-if="sIndex === vuln.Path.length - 1">Sink</span>
                  <span v-else>Step {{ sIndex }}</span>
                  <span class="step-line">L{{ step.Line }}</span>
                </div>
                <div class="step-code">{{ step.Code }}</div>
              </div>
            </div>
          </div>
        </div>
      </a-layout-sider>

      <a-layout>
        <a-layout-header style="background: #fff; padding: 0 20px; border-bottom: 1px solid #f0f0f0; display: flex; align-items: center;">
          <a-input-search
            v-model:value="filePath"
            placeholder="Enter absolute file path"
            enter-button="Scan"
            size="large"
            @search="scanFile"
            :loading="loading"
          />
        </a-layout-header>
        
        <a-layout-content style="margin: 0; display: flex; overflow: hidden; position: relative;">
          <!-- Code View -->
          <div class="code-panel">
            <div class="panel-title">Source Code: {{ currentFile }}</div>
            <div class="code-wrapper">
               <div class="line-numbers">
                  <div 
                    v-for="(_, i) in fileLines" 
                    :key="i" 
                    class="line-num-item" 
                    :class="{ 'highlight-num': highlightedLine === i + 1 }"
                    :id="'line-num-' + (i + 1)"
                  >
                    {{ i + 1 }}
                  </div>
               </div>
               <div class="code-content" ref="codeContentRef">
                  <pre><code class="hljs" v-html="highlightedCode"></code></pre>
                  <!-- Line Highlight Overlay -->
                  <div 
                    v-if="highlightedLine > 0" 
                    class="line-highlight-overlay"
                    :style="{ top: ((highlightedLine - 1) * 21 + 10) + 'px' }"
                  ></div>
               </div>
            </div>
          </div>

          <!-- Info Panel -->
          <div class="info-panel">
            <a-tabs v-model:activeKey="activeTab" :tabBarStyle="{ paddingLeft: '16px' }">
              <a-tab-pane key="logs" tab="Logs">
                <div class="logs-container">
                  <div v-for="(log, i) in logs" :key="i" class="log-item">{{ log }}</div>
                </div>
              </a-tab-pane>
              <a-tab-pane key="graph" tab="CFG" v-if="irData">
                 <div class="cfg-wrapper" ref="cfgWrapper">
                    <div id="mermaid-graph" class="mermaid-container"></div>
                 </div>
              </a-tab-pane>
              <a-tab-pane key="ir" tab="IR" v-if="irData">
                <div class="ir-container">
                   <div v-for="(fn, name) in irData.functions" :key="name" class="ir-function">
                     <div class="ir-func-name">func {{ name }}:</div>
                     <div v-for="(bb, bid) in fn.blocks" :key="bid" class="ir-block">
                        <div class="block-header">{{ bid }}:</div>
                        <div v-for="inst in bb.instructions" :key="inst.id" class="inst">
                           <span class="inst-indent">  </span>
                           <span class="inst-op">{{ inst.op }}</span>
                           <span class="inst-args" v-if="inst.operands && inst.operands.length"> {{ inst.operands.join(', ') }}</span>
                           <span class="inst-meta" v-if="inst.result"> -> {{ inst.result }}</span>
                        </div>
                     </div>
                   </div>
                </div>
              </a-tab-pane>
              <a-tab-pane key="ast" tab="AST" v-if="astData">
                <div class="ast-container">
                    <a-tree
                        v-if="astData"
                        :tree-data="[astData]"
                        :default-expand-all="true"
                        :show-line="true"
                        @select="onAstSelect"
                    >
                        <template #title="{ title, line }">
                            <span class="ast-node-title">{{ title }}</span>
                            <span v-if="line > 0" class="ast-node-line"> :L{{ line }}</span>
                        </template>
                    </a-tree>
                </div>
              </a-tab-pane>
            </a-tabs>
          </div>
        </a-layout-content>
      </a-layout>
    </a-layout>
  </div>
</template>

<script setup>
import { ref, computed, nextTick, watch } from 'vue';
import axios from 'axios';
import mermaid from 'mermaid';
import hljs from 'highlight.js/lib/core';
import go from 'highlight.js/lib/languages/go';
import java from 'highlight.js/lib/languages/java';
import 'highlight.js/styles/github.css';
import panzoom from 'panzoom';

hljs.registerLanguage('go', go);
hljs.registerLanguage('java', java);

mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });

const filePath = ref('examples/go/vuln.go');
const currentFile = ref('');
const fileContent = ref('');
const vulnerabilities = ref([]);
const logs = ref([]);
const irData = ref(null);
const astData = ref(null);
const loading = ref(false);
const selectedVulnIndex = ref(-1);
const highlightedLine = ref(-1);
const highlightedBlocks = ref(new Set());
const activeFunction = ref(null);
const activeTab = ref('logs');
const cfgWrapper = ref(null);
const codeContentRef = ref(null);

watch(activeTab, (newTab) => {
  if (newTab === 'graph' && irData.value) {
    nextTick(() => renderCFG());
  }
});

const fileLines = computed(() => {
  return fileContent.value ? fileContent.value.split('\n') : [];
});

const highlightedCode = computed(() => {
    if (!fileContent.value) return '';
    const ext = currentFile.value.endsWith('.go') ? 'go' : 'java';
    try {
        return hljs.highlight(fileContent.value, { language: ext }).value;
    } catch (e) {
        return fileContent.value;
    }
});

const getSeverityColor = (severity) => {
  switch (severity) {
    case 'CRITICAL': return 'red';
    case 'HIGH': return 'orange';
    case 'MEDIUM': return 'yellow';
    default: return 'blue';
  }
};

const scanFile = async () => {
  if (!filePath.value) return;
  loading.value = true;
  vulnerabilities.value = [];
  logs.value = [];
  irData.value = null;
  astData.value = null;
  selectedVulnIndex.value = -1;
  highlightedLine.value = -1;
  highlightedBlocks.value = new Set();
  activeFunction.value = null;

  try {
    // 1. Analyze
    const res = await axios.get(`http://localhost:8080/api/analyze?file=${encodeURIComponent(filePath.value)}`);
    const data = res.data;
    
    vulnerabilities.value = data.vulnerabilities || [];
    logs.value = data.logs || [];
    irData.value = data.ir;
    astData.value = data.ast;
    currentFile.value = data.file;

    // 2. Load File Content
    const fileRes = await axios.get(`http://localhost:8080/api/file?path=${encodeURIComponent(data.file)}`);
    fileContent.value = fileRes.data;

    // 3. Render Graph if available
    if (irData.value) {
      activeTab.value = 'graph';
      nextTick(() => renderCFG());
    } else {
      activeTab.value = 'logs';
    }

  } catch (err) {
    logs.value.push(`Error: ${err.message}`);
    if (err.response && err.response.data && err.response.data.logs) {
        logs.value = [...logs.value, ...err.response.data.logs];
    }
  } finally {
    loading.value = false;
  }
};

const selectVuln = (index) => {
  selectedVulnIndex.value = index;
  const v = vulnerabilities.value[index];
  if (v) {
    highlightLine(v.Sink.Line);

    // Collect blocks and function for CFG highlighting
    const blocks = new Set();
    let funcName = null;
    
    // Check Source
    if (v.Source) {
        if (v.Source.BlockID) blocks.add(v.Source.BlockID);
        if (v.Source.Function) funcName = v.Source.Function;
    }

    // Check Path
    if (v.Path) {
      v.Path.forEach(node => {
         if (node.BlockID) blocks.add(node.BlockID);
         if (node.Function && !funcName) funcName = node.Function;
      });
    }
    
    // Check Sink
    if (v.Sink) {
        if (v.Sink.BlockID) blocks.add(v.Sink.BlockID);
        if (v.Sink.Function && !funcName) funcName = v.Sink.Function;
    }

    highlightedBlocks.value = blocks;
    // Update active function only if found, otherwise keep full view or previous
    if (funcName) {
       activeFunction.value = funcName;
    }
    
    // Re-render CFG if visible
    if (activeTab.value === 'graph') {
       nextTick(() => renderCFG());
    }
  }
};

const onAstSelect = (selectedKeys, { node }) => {
    if (node.line > 0) {
        highlightLine(node.line);
    }
};

const highlightLine = (line) => {
  highlightedLine.value = line;
  nextTick(() => {
    // Manually calculate scroll position to center the line
    const wrapper = codeContentRef.value ? codeContentRef.value.parentElement : null;
    if (wrapper && line > 0) {
        const lineHeight = 21;
        const paddingTop = 10;
        // Target position of the line top
        const lineTop = (line - 1) * lineHeight + paddingTop;
        // Center view: lineTop - halfHeight + halfLine
        const targetScroll = lineTop - (wrapper.clientHeight / 2) + (lineHeight / 2);
        
        wrapper.scrollTo({ top: targetScroll, behavior: 'smooth' });
    }
  });
};

const renderCFG = async () => {
  if (!irData.value || !irData.value.functions) return;
  
  // Vertical layout (TD)
  let graphDef = 'graph TD\n';
  // Styling
  graphDef += 'classDef default fill:#fff,stroke:#333,stroke-width:1px;\n';
  graphDef += 'classDef highlighted fill:#e6f7ff,stroke:#1890ff,stroke-width:2px;\n';
  graphDef += 'classDef active fill:#ffcccc,stroke:#ff0000,stroke-width:3px;\n';

  // Determine which functions to render
  const functionsToRender = activeFunction.value && irData.value.functions[activeFunction.value]
      ? { [activeFunction.value]: irData.value.functions[activeFunction.value] }
      : irData.value.functions;

  for (const [name, fn] of Object.entries(functionsToRender)) {
    graphDef += `subgraph ${name}\n`;
    graphDef += `direction TB\n`; // Ensure top-bottom inside subgraph
    for (const [bid, bb] of Object.entries(fn.blocks)) {
      // Build Instruction String
      const instStr = bb.instructions.map(i => {
          let s = i.op;
          if (i.operands && i.operands.length) s += ' ' + i.operands.join(', ');
          if (i.result) s += ' -> ' + i.result;
          // Simple escaping
          return s.replace(/"/g, "'").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      }).join('<br/>');

      // Label with ID and Code
      // Wrap in div for left alignment
      let label = `<div style='text-align:left;font-family:monospace'><b>${bid}</b><br/>${instStr}</div>`;
      
      // Add click event class
      graphDef += `${bid}["${label}"]:::clickable\n`;
      
      // Add style if highlighted
      if (highlightedBlocks.value.has(bid)) {
          graphDef += `style ${bid} fill:#ffcccc,stroke:#ff0000,stroke-width:2px\n`;
      }

      bb.successors.forEach(succ => {
        graphDef += `${bid} --> ${succ}\n`;
      });
    }
    graphDef += 'end\n';
  }
  
  // Add click callback
  // Mermaid click syntax: click NodeId callback
  // But we use DOM interaction post-render for better control
  
  const element = document.getElementById('mermaid-graph');
  if (element) {
    element.innerHTML = graphDef;
    element.removeAttribute('data-processed');
    try {
        const { svg } = await mermaid.render('mermaid-svg', graphDef);
        element.innerHTML = svg;
        
        // Initialize Panzoom
        if (cfgWrapper.value) {
            const svgEl = element.querySelector('svg');
            if (svgEl) {
                panzoom(svgEl, {
                    maxZoom: 5,
                    minZoom: 0.1
                });
                svgEl.style.height = '100%';
                svgEl.style.width = '100%';
            }
        }
    } catch (e) {
        console.error(e);
    }
  }
};
</script>

<style scoped>
.logo {
  height: 64px;
  line-height: 64px;
  padding-left: 20px;
  font-size: 20px;
  font-weight: bold;
  background: #fff;
  color: #1890ff;
  border-bottom: 1px solid #f0f0f0;
}

.vuln-list {
  padding: 10px;
  overflow-y: auto;
  height: calc(100vh - 64px);
}

.vuln-item {
  background: #fff;
  border: 1px solid #f0f0f0;
  border-radius: 6px;
  padding: 12px;
  margin-bottom: 10px;
  cursor: pointer;
  transition: all 0.3s;
}

.vuln-item:hover {
  border-color: #1890ff;
  box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}

.vuln-item.active {
  background: #e6f7ff;
  border-color: #1890ff;
}

.vuln-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 5px;
}

.vuln-type {
  font-weight: 600;
  color: #333;
}

.vuln-steps {
  margin-top: 10px;
  border-top: 1px solid #e8e8e8;
  padding-top: 10px;
}

.step-item {
  font-size: 12px;
  padding: 4px 8px;
  border-radius: 4px;
  margin-bottom: 4px;
  cursor: pointer;
}

.step-item:hover {
  background: rgba(24, 144, 255, 0.1);
}

.step-label {
  color: #888;
  display: flex;
  justify-content: space-between;
}

/* Code Panel */
.code-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  border-right: 1px solid #f0f0f0;
  overflow: hidden;
}

.panel-title {
  padding: 10px 20px;
  background: #fafafa;
  border-bottom: 1px solid #f0f0f0;
  font-weight: 600;
  font-size: 14px;
}

.code-wrapper {
  flex: 1;
  display: flex;
  overflow: auto;
  position: relative;
  background: #fff;
}

.line-numbers {
  width: 40px;
  background: #fafafa;
  border-right: 1px solid #f0f0f0;
  text-align: right;
  padding: 10px 5px;
  font-family: monospace;
  font-size: 13px;
  line-height: 21px; /* Match code line height */
  color: #999;
  user-select: none;
}

.line-num-item {
    height: 21px;
}

.highlight-num {
    color: #1890ff;
    font-weight: bold;
}

.code-content {
  flex: 1;
  padding: 10px;
  position: relative;
  font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  line-height: 21px;
}

pre {
    margin: 0;
    padding: 0;
    background: transparent;
}

code.hljs {
    padding: 0;
    background: transparent;
}

.line-highlight-overlay {
    position: absolute;
    left: 0;
    right: 0;
    height: 21px;
    background: rgba(255, 255, 0, 0.2);
    pointer-events: none;
    z-index: 0; /* Behind text if possible, but text is in pre. Need pre z-index > overlay */
}

/* Info Panel */
.info-panel {
  width: 400px;
  background: #fff;
  display: flex;
  flex-direction: column;
  border-left: 1px solid #f0f0f0; /* Add border for separation */
  z-index: 10; /* Ensure logs are above code if needed, but flex should handle it */
}

.logs-container {
  padding: 10px;
  height: calc(100vh - 120px);
  overflow-y: auto;
  background: #1e1e1e;
  color: #fff;
  font-family: monospace;
  font-size: 12px;
}

.log-item {
  margin-bottom: 4px;
  border-bottom: 1px solid #333;
  padding-bottom: 2px;
}

.cfg-wrapper {
    height: calc(100vh); /* Adjust height */
    overflow: hidden; /* Panzoom handles movement */
    background: #fafafa;
    position: relative;
    border-bottom: 1px solid #ddd;
}

/* IR Code Style */
.ir-container {
    background: #282c34;
    color: #abb2bf;
    padding: 20px;
    font-family: 'Fira Code', 'Menlo', 'Monaco', monospace;
    font-size: 13px;
    line-height: 1.5;
    height: calc(100vh - 120px);
    overflow-y: auto;
}

.ir-function {
    margin-bottom: 20px;
}

.ir-func-name {
    color: #c678dd; /* Purple */
    font-weight: bold;
    margin-bottom: 5px;
}

.ir-block {
    margin-top: 10px;
}

.block-header {
    color: #e5c07b; /* Yellow */
    font-weight: bold;
    margin-bottom: 2px;
}

.inst {
    display: flex;
    white-space: pre;
}

.inst-indent {
    width: 20px;
}

.inst-op {
    color: #61afef; /* Blue */
    font-weight: bold;
    min-width: 60px;
    display: inline-block;
}

.inst-args {
    color: #98c379; /* Green */
}

.inst-meta {
    color: #5c6370; /* Grey */
    font-style: italic;
    margin-left: 10px;
}

.ast-container {
    padding: 10px;
    height: calc(100vh - 120px);
    overflow-y: auto;
    background: #fff;
}

.ast-node-title {
    font-family: monospace;
    font-size: 13px;
    color: #333;
}

.ast-node-line {
    color: #1890ff;
    font-size: 11px;
    margin-left: 8px;
    cursor: pointer;
}
</style>
