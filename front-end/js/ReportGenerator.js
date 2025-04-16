// ReportGenerator.js - Componente para geração de relatórios

app.component('report-generator', {
    props: {
        reportData: {
            type: Object,
            required: true
        },
        savedResults: {
            type: Array,
            default: () => []
        },
        isLoading: {
            type: Boolean,
            default: false
        }
    },
    methods: {
        generateReport() {
            this.$emit('generate-report');
        },
        downloadReport() {
            this.$emit('download-report');
        },
        formatScanType(type) {
            if (!type) return 'Desconhecido';

            const types = {
                'port_scan': 'Scanner de Portas',
                'directory_scan': 'Scanner de Diretórios',
                'subdomain_scan': 'Scanner de Subdomínios',
                'tech_scan': 'Scanner de Tecnologias',
                'plugin_scan': 'Scanner de Plugins',
                'sqli_scan': 'SQL Injection',
                'xss_scan': 'Cross-Site Scripting',
                'redirect_scan': 'Open Redirect',
                'bruteforce': 'Brute Force',
                'bypass_403': 'Bypass 403',
                'hash_analyze': 'Análise de Hash',
                'crypto_crack': 'Quebra de Criptografia'
            };

            return types[type] || type.replace('_', ' ').toUpperCase();
        },
        formatTimestamp(timestamp) {
            if (!timestamp) return '';
            const date = new Date(timestamp);
            return date.toLocaleString();
        }
    },
    template: `
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <!-- Formulário do Gerador de Relatórios -->
            <div class="bg-darker p-4 rounded-lg shadow">
                <h3 class="text-lg font-semibold mb-4 text-primary">Gerador de Relatórios</h3>
                
                <form @submit.prevent="generateReport">
                    <div class="mb-4">
                        <label class="block text-gray-300 mb-2">Título do Relatório</label>
                        <input type="text" v-model="reportData.title" 
                               class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                               placeholder="Relatório de Pentesting">
                    </div>
                    
                    <div class="mb-4">
                        <label class="block text-gray-300 mb-2">Nome da Empresa</label>
                        <input type="text" v-model="reportData.companyName" 
                               class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                               placeholder="Empresa XYZ">
                    </div>
                    
                    <div class="mb-4">
                        <label class="block text-gray-300 mb-2">Autor</label>
                        <input type="text" v-model="reportData.author" 
                               class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                               placeholder="Seu nome">
                    </div>
                    
                    <div class="mb-4">
                        <label class="block text-gray-300 mb-2">Formato</label>
                        <select v-model="reportData.format" 
                                class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary">
                            <option value="markdown">Markdown</option>
                            <option value="pdf">PDF</option>
                        </select>
                    </div>
                    
                    <div class="mb-4">
                        <label class="block text-gray-300 mb-2">Resultados para Incluir</label>
                        <div class="max-h-48 overflow-y-auto bg-dark p-2 border border-gray-700 rounded">
                            <div v-if="savedResults.length === 0" class="text-gray-500 text-center py-2">
                                Nenhum resultado salvo
                            </div>
                            <div v-for="(result, index) in savedResults" :key="index" class="py-1 px-2 flex items-center">
                                <input type="checkbox" :id="'result-' + index" v-model="reportData.selectedResults" :value="index" class="mr-2">
                                <label :for="'result-' + index" class="text-gray-300 text-sm">
                                    {{ formatScanType(result.scan_type) }} - {{ result.target }} ({{ formatTimestamp(result.timestamp) }})
                                </label>
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" 
                            class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                            :disabled="isLoading || reportData.selectedResults.length === 0">
                        <i class="fas fa-file-alt mr-2"></i> Gerar Relatório
                    </button>
                </form>
            </div>
            
            <!-- Prévia do relatório -->
            <div class="md:col-span-2 bg-darker rounded-lg shadow overflow-hidden">
                <div class="p-4 border-b border-gray-800 flex justify-between items-center">
                    <h3 class="text-lg font-semibold text-primary">Prévia do Relatório</h3>
                    <div v-if="reportData.result">
                        <button @click="downloadReport" class="text-sm bg-primary hover:bg-blue-600 text-white py-1 px-3 rounded">
                            <i class="fas fa-download mr-1"></i> Download
                        </button>
                    </div>
                </div>
                
                <div class="p-4">
                    <!-- Resultado - Markdown -->
                    <div v-if="reportData.result && reportData.format === 'markdown'" class="bg-dark p-4 rounded overflow-auto max-h-96">
                        <pre><code>{{ reportData.result.content }}</code></pre>
                    </div>
                    
                    <!-- Resultado - PDF -->
                    <div v-else-if="reportData.result && reportData.format === 'pdf'" class="text-center py-8">
                        <i class="fas fa-file-pdf text-4xl text-primary mb-4"></i>
                        <p class="text-gray-300 mb-4">Relatório PDF gerado com sucesso!</p>
                        <button @click="downloadReport" class="bg-primary hover:bg-blue-600 text-white py-2 px-4 rounded">
                            <i class="fas fa-download mr-1"></i> Download do PDF
                        </button>
                    </div>
                    
                    <!-- Nenhum resultado ainda -->
                    <div v-else class="text-center py-8 text-gray-500">
                        <i class="fas fa-file-alt text-4xl mb-4"></i>
                        <p>Selecione os resultados de scan e clique em "Gerar Relatório" para começar.</p>
                    </div>
                </div>
            </div>
        </div>
    `
});