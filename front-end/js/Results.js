// Results.js - Componente para exibição de resultados

app.component('results-component', {
    props: {
        results: {
            type: Object,
            default: null
        },
        resultsType: {
            type: String,
            required: true
        },
        mode: {
            type: String,
            default: null
        }
    },
    methods: {
        saveResults() {
            this.$emit('save-results');
        },
        clearResults() {
            this.$emit('clear-results');
        },
        copyToClipboard(text) {
            this.$emit('copy-to-clipboard', text);
        },
        getStatusClass(status) {
            if (status >= 200 && status < 300) return 'terminal-success';
            if (status >= 300 && status < 400) return 'terminal-info';
            if (status >= 400 && status < 500) return 'terminal-warning';
            if (status >= 500) return 'terminal-error';
            return '';
        },
        formatDuration(seconds) {
            const minutes = Math.floor(seconds / 60);
            const remainingSeconds = seconds % 60;
            return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
        }
    },
    template: `
        <div class="md:col-span-2 bg-darker rounded-lg shadow overflow-hidden">
            <div class="p-4 border-b border-gray-800 flex justify-between items-center">
                <h3 class="text-lg font-semibold text-primary">Resultados</h3>
                <div v-if="results">
                    <button @click="saveResults" class="text-sm bg-dark hover:bg-gray-700 text-gray-300 py-1 px-3 rounded mr-2">
                        <i class="fas fa-save mr-1"></i> Salvar
                    </button>
                    <button @click="clearResults" class="text-sm bg-dark hover:bg-gray-700 text-gray-300 py-1 px-3 rounded">
                        <i class="fas fa-trash mr-1"></i> Limpar
                    </button>
                </div>
            </div>
            
            <div class="p-4">
                <!-- Sem resultados -->
                <div v-if="!results" class="text-center py-8 text-gray-500">
                    <i :class="['text-4xl mb-4', $parent.toolIcon]"></i>
                    <p class="text-lg">Inicie um scan para ver os resultados aqui.</p>
                </div>
                
                <!-- Resultados do Scanner de Portas -->
                <div v-else-if="resultsType === 'port' && results" class="terminal">
                    <div class="terminal-header">
                        <span><i class="fas fa-terminal mr-2"></i> Resultado do Scan</span>
                        <span>Alvo: {{ results.host }}</span>
                    </div>
                    
                    <div class="terminal-prompt">
                        Escaneando {{ results.host }} ({{ results.scanned_range }})
                    </div>
                    
                    <div class="terminal-output mt-2">
                        <p class="mb-2">Scan concluído em {{ results.scan_time }}s</p>
                        <p class="mb-2">Portas abertas encontradas: <span class="terminal-success">{{ results.total_open }}</span></p>
                        
                        <div v-if="results.open_ports && results.open_ports.length > 0" class="mt-4">
                            <p class="terminal-info mb-2">Detalhes das portas:</p>
                            <table class="w-full border-collapse">
                                <thead>
                                    <tr class="text-left">
                                        <th class="py-1 pr-4">Porta</th>
                                        <th class="py-1 pr-4">Serviço</th>
                                        <th class="py-1 pr-4">Produto</th>
                                        <th class="py-1">Versão</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="port in results.open_ports" :key="port">
                                        <td class="py-1 pr-4">{{ port }}</td>
                                        <td class="py-1 pr-4">{{ results.port_details && results.port_details[port] ? results.port_details[port].service : 'N/A' }}</td>
                                        <td class="py-1 pr-4">{{ results.port_details && results.port_details[port] ? results.port_details[port].product : 'N/A' }}</td>
                                        <td class="py-1">{{ results.port_details && results.port_details[port] ? results.port_details[port].version : 'N/A' }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        <div v-else class="terminal-warning mt-4">
                            Nenhuma porta aberta encontrada.
                        </div>
                    </div>
                </div>
                
                <!-- Resultados do Scanner de Diretórios -->
                <div v-else-if="resultsType === 'directory' && results" class="terminal">
                    <div class="terminal-header">
                        <span><i class="fas fa-terminal mr-2"></i> Resultado do Scan</span>
                        <span>Alvo: {{ results.target }}</span>
                    </div>
                    
                    <div class="terminal-prompt">
                        Escaneando {{ results.target }}
                    </div>
                    
                    <div class="terminal-output mt-2">
                        <p class="mb-2">Scan concluído em {{ results.scan_time }}s</p>
                        <p class="mb-2">Diretórios/Arquivos encontrados: <span class="terminal-success">{{ results.directories ? results.directories.length : 0 }}</span></p>
                        
                        <div v-if="results.directories && results.directories.length > 0" class="mt-4">
                            <p class="terminal-info mb-2">Resultados encontrados:</p>
                            <table class="w-full border-collapse">
                                <thead>
                                    <tr class="text-left">
                                        <th class="py-1 pr-4">URL</th>
                                        <th class="py-1 pr-4">Status</th>
                                        <th class="py-1">Tamanho</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="(dir, index) in results.directories" :key="index">
                                        <td class="py-1 pr-4 break-all">{{ dir.url }}</td>
                                        <td class="py-1 pr-4">
                                            <span :class="getStatusClass(dir.status)">{{ dir.status }}</span>
                                        </td>
                                        <td class="py-1">{{ dir.size }} bytes</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        <div v-else class="terminal-warning mt-4">
                            Nenhum diretório ou arquivo encontrado.
                        </div>
                    </div>
                </div>
                
                <!-- Resultados do Scanner de Subdomínios -->
                <div v-else-if="resultsType === 'subdomain' && results" class="terminal">
                    <div class="terminal-header">
                        <span><i class="fas fa-terminal mr-2"></i> Resultado do Scan</span>
                        <span>Alvo: {{ results.target }}</span>
                    </div>
                    
                    <div class="terminal-prompt">
                        Escaneando {{ results.target }}
                    </div>
                    
                    <div class="terminal-output mt-2">
                        <p class="mb-2">Scan concluído em {{ results.scan_time }}s</p>
                        <p class="mb-2">Subdomínios encontrados: <span class="terminal-success">{{ results.subdomains ? results.subdomains.length : 0 }}</span></p>
                        
                        <div v-if="results.subdomains && results.subdomains.length > 0" class="mt-4">
                            <p class="terminal-info mb-2">Resultados encontrados:</p>
                            <table class="w-full border-collapse">
                                <thead>
                                    <tr class="text-left">
                                        <th class="py-1 pr-4">Subdomínio</th>
                                        <th class="py-1 pr-4">IP</th>
                                        <th class="py-1">Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="(sub, index) in results.subdomains" :key="index">
                                        <td class="py-1 pr-4">{{ sub.name }}</td>
                                        <td class="py-1 pr-4">{{ sub.ip }}</td>
                                        <td class="py-1">
                                            <span v-if="sub.status" :class="getStatusClass(sub.status)">{{ sub.status }}</span>
                                            <span v-else class="text-gray-500">Desconhecido</span>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        <div v-else class="terminal-warning mt-4">
                            Nenhum subdomínio encontrado.
                        </div>
                    </div>
                </div>
                
                <!-- Outros tipos de resultados seguiriam um padrão semelhante -->
                
                <!-- Resultados do Analisador de Hash -->
                <div v-else-if="resultsType === 'hash' && results" class="terminal">
                    <div v-if="mode === 'analyze'">
                        <div class="terminal-header">
                            <span><i class="fas fa-fingerprint mr-2"></i> Análise de Hash</span>
                            <span>{{ results.hash }}</span>
                        </div>
                        
                        <div class="terminal-output mt-4">
                            <!-- Tipos identificados -->
                            <div class="mb-4">
                                <p class="terminal-info mb-2">Tipos de Hash Identificados:</p>
                                <div v-if="results.identified_types && results.identified_types.length > 0">
                                    <ul>
                                        <li v-for="(type, index) in results.identified_types" :key="index" class="py-1">
                                            <span class="text-primary">{{ type.name }}</span> ({{ type.type }})
                                        </li>
                                    </ul>
                                </div>
                                <div v-else class="terminal-warning">
                                    Nenhum tipo de hash reconhecido
                                </div>
                            </div>
                            
                            <!-- Informações do Hash -->
                            <div class="mb-4">
                                <p class="terminal-info mb-2">Informações do Hash:</p>
                                <table class="w-full">
                                    <tr>
                                        <td class="pr-4 py-1">Comprimento:</td>
                                        <td class="font-mono">{{ results.length }} caracteres</td>
                                    </tr>
                                    <tr>
                                        <td class="pr-4 py-1">Entropia:</td>
                                        <td class="font-mono">{{ results.entropy?.toFixed(2) || 'N/A' }}</td>
                                    </tr>
                                    <tr>
                                        <td class="pr-4 py-1">Base64:</td>
                                        <td>
                                            <span v-if="results.is_base64" class="terminal-success">Sim</span>
                                            <span v-else class="terminal-error">Não</span>
                                        </td>
                                    </tr>
                                    <tr v-if="results.base64_decoded">
                                        <td class="pr-4 py-1">Decodificado (Base64):</td>
                                        <td class="font-mono">{{ results.base64_decoded }}</td>
                                    </tr>
                                </table>
                            </div>
                            
                            <!-- Distribuição de Caracteres -->
                            <div class="mb-4">
                                <p class="terminal-info mb-2">Distribuição de Caracteres:</p>
                                <table class="w-full">
                                    <tr v-for="(value, key) in results.character_distribution" :key="key">
                                        <td class="capitalize pr-4 py-1">{{ key }}:</td>
                                        <td class="font-mono">{{ value.count }} ({{ value.percentage }}%)</td>
                                    </tr>
                                </table>
                            </div>
                            
                            <!-- Recomendações -->
                            <div class="mb-4" v-if="results.recommendations && results.recommendations.length > 0">
                                <p class="terminal-info mb-2">Recomendações:</p>
                                <ul>
                                    <li v-for="(rec, index) in results.recommendations" :key="index" class="py-1 pl-4">
                                        - {{ rec }}
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    
                    <div v-else-if="mode === 'generate'">
                        <div class="terminal-header">
                            <span><i class="fas fa-cog mr-2"></i> Hashes Gerados</span>
                            <span>Input: {{ results.input }}</span>
                        </div>
                        
                        <div class="terminal-output mt-4">
                            <table class="w-full">
                                <thead>
                                    <tr>
                                        <th class="text-left py-2">Algoritmo</th>
                                        <th class="text-left py-2">Hash</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="(hash, algo) in results.hashes" :key="algo">
                                        <td class="pr-4 py-2 font-semibold">{{ algo }}</td>
                                        <td class="font-mono py-2">
                                            {{ hash }}
                                            <button @click="copyToClipboard(hash)" class="ml-2 text-primary hover:text-blue-400">
                                                <i class="fas fa-copy"></i>
                                            </button>
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <!-- Resultados da Quebra de Criptografia -->
                <div v-else-if="resultsType === 'crypto' && results" class="terminal">
                    <div v-if="mode === 'crack'">
                        <div class="terminal-header">
                            <span><i class="fas fa-hammer mr-2"></i> Resultado da Quebra</span>
                            <span>Hash: {{ results.hash }}</span>
                        </div>
                        
                        <div class="terminal-output mt-4">
                            <div v-if="results.success" class="mb-4">
                                <p class="terminal-success mb-2">Hash quebrado com sucesso!</p>
                                <div class="bg-green-900 bg-opacity-20 p-3 rounded">
                                    <p class="mb-2">Texto original:</p>
                                    <p class="font-mono text-xl text-green-400">{{ results.plaintext }}</p>
                                </div>
                            </div>
                            <div v-else class="mb-4">
                                <p class="terminal-error mb-2">Não foi possível quebrar o hash.</p>
                                <p>{{ results.message }}</p>
                            </div>
                            
                            <div class="mb-4">
                                <p class="terminal-info mb-2">Detalhes:</p>
                                <table class="w-full">
                                    <tr>
                                        <td class="pr-4 py-1">Tipo de Hash:</td>
                                        <td class="font-semibold">{{ results.hash_type.toUpperCase() }}</td>
                                    </tr>
                                    <tr>
                                        <td class="pr-4 py-1">Tentativas:</td>
                                        <td>{{ results.attempts }} de {{ results.total_words }}</td>
                                    </tr>
                                    <tr>
                                        <td class="pr-4 py-1">Tempo:</td>
                                        <td>{{ results.crack_time }} segundos</td>
                                    </tr>
                                </table>
                            </div>
                        </div>
                    </div>
                    
                    <div v-else-if="mode === 'estimate'">
                        <div class="terminal-header">
                            <span><i class="fas fa-clock mr-2"></i> Estimativa de Tempo</span>
                            <span>Hash: {{ results.hash_type.toUpperCase() }}</span>
                        </div>
                        
                        <div class="terminal-output mt-4">
                            <div class="mb-4">
                                <p class="terminal-info mb-2">Detalhes da Estimativa:</p>
                                <table class="w-full">
                                    <tr>
                                        <td class="pr-4 py-1">Tipo de Hash:</td>
                                        <td class="font-semibold">{{ results.hash_type.toUpperCase() }}</td>
                                    </tr>
                                    <tr>
                                        <td class="pr-4 py-1">Tamanho da Wordlist:</td>
                                        <td>{{ results.wordlist_size.toLocaleString() }} palavras</td>
                                    </tr>
                                    <tr>
                                        <td class="pr-4 py-1">Tempo Estimado:</td>
                                        <td>{{ results.estimated_time }}</td>
                                    </tr>
                                    <tr>
                                        <td class="pr-4 py-1">Velocidade de Hash:</td>
                                        <td>{{ (results.hash_speed / 1000000).toFixed(0) }} Milhões/s</td>
                                    </tr>
                                </table>
                            </div>
                            
                            <div class="mt-4 p-3 bg-yellow-900 bg-opacity-20 rounded">
                                <p class="text-yellow-400">
                                    <i class="fas fa-exclamation-triangle mr-2"></i> Esta é apenas uma estimativa e pode variar significativamente dependendo do hardware utilizado.
                                </p>
                            </div>
                        </div>
                    </div>
                    
                    <div v-else-if="mode === 'decode'">
                        <div class="terminal-header">
                            <span><i class="fas fa-unlock mr-2"></i> Resultado da Decodificação</span>
                            <span>Tipo: {{ results.encoding_type }}</span>
                        </div>
                        
                        <div class="terminal-output mt-4">
                            <div v-if="results.success" class="mb-4">
                                <p class="terminal-success mb-2">Decodificação bem-sucedida!</p>
                                
                                <!-- Para Cifra de César com múltiplos resultados -->
                                <div v-if="results.encoding_type === 'caesar' && results.results">
                                    <p class="mb-2">Possíveis decodificações:</p>
                                    <div class="max-h-60 overflow-y-auto bg-dark p-2 rounded">
                                        <div v-for="(result, index) in results.results" :key="index" class="mb-2 p-2 border-b border-gray-700">
                                            <div class="flex justify-between">
                                                <span class="font-semibold">Deslocamento {{ result.shift }}:</span>
                                                <button @click="copyToClipboard(result.text)" class="text-primary hover:text-blue-400">
                                                    <i class="fas fa-copy"></i>
                                                </button>
                                            </div>
                                            <p class="font-mono mt-1">{{ result.text }}</p>
                                        </div>
                                    </div>
                                </div>
                                
                                <!-- Para outros tipos de decodificação -->
                                <div v-else class="bg-green-900 bg-opacity-20 p-3 rounded">
                                    <div class="flex justify-between items-start">
                                        <p class="mb-2">Texto decodificado:</p>
                                        <button @click="copyToClipboard(results.decoded)" class="text-primary hover:text-blue-400">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                    <p class="font-mono">{{ results.decoded }}</p>
                                </div>
                            </div>
                            <div v-else class="mb-4">
                                <p class="terminal-error mb-2">Não foi possível decodificar o texto.</p>
                                <p>{{ results.error }}</p>
                            </div>
                            
                            <div class="mb-4">
                                <p class="terminal-info mb-2">Detalhes:</p>
                                <table class="w-full">
                                    <tr>
                                        <td class="pr-4 py-1">Tipo de Codificação:</td>
                                        <td class="font-semibold">{{ results.encoding_type }}</td>
                                    </tr>
                                    <tr v-if="results.shift">
                                        <td class="pr-4 py-1">Deslocamento:</td>
                                        <td>{{ results.shift }}</td>
                                    </tr>
                                    <tr>
                                        <td class="pr-4 py-1">Tempo:</td>
                                        <td>{{ results.decode_time }} segundos</td>
                                    </tr>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Resultados para outros tipos de scans -->
                <div v-else class="text-center py-8 text-gray-500">
                    <i :class="['text-4xl mb-4', $parent.toolIcon]"></i>
                    <p class="text-lg">Tipo de resultado não suportado: {{ resultsType }}</p>
                </div>
            </div>
        </div>
    `
});