// ScanForm.js - Componente para formulários de scan

app.component('scan-form', {
    props: {
        formType: {
            type: String,
            required: true
        },
        scanParams: {
            type: Object,
            required: true
        },
        isLoading: {
            type: Boolean,
            default: false
        }
    },
    methods: {
        submitForm() {
            this.$emit('run-scan');
        },
        generateHash() {
            this.$emit('generate-hash');
        },
        decodeString() {
            this.$emit('decode-string');
        },
        estimateTime() {
            this.$emit('estimate-time');
        }
    },
    template: `
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div class="bg-darker p-4 rounded-lg shadow md:col-span-1">
                <!-- Formulário de Scanner de Portas -->
                <div v-if="formType === 'port'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Scanner de Portas</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Alvo (IP ou Domínio)</label>
                            <input type="text" v-model="scanParams.target" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="exemplo.com ou 192.168.1.1">
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Range de Portas</label>
                            <input type="text" v-model="scanParams.portRange" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="1-1000">
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-play mr-2"></i> Iniciar Scan
                        </button>
                    </form>
                </div>
                
                <!-- Formulário de Scanner de Diretórios -->
                <div v-if="formType === 'directory'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Scanner de Diretórios</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">URL Alvo</label>
                            <input type="text" v-model="scanParams.target" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="https://exemplo.com">
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Wordlist</label>
                            <select v-model="scanParams.wordlist" 
                                    class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary">
                                <option value="common">Comum</option>
                                <option value="big">Grande</option>
                                <option value="small">Pequena</option>
                            </select>
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Extensões</label>
                            <input type="text" v-model="scanParams.extensions" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="php,html,js,txt">
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-play mr-2"></i> Iniciar Scan
                        </button>
                    </form>
                </div>
                
                <!-- Formulário de Scanner de Subdomínios -->
                <div v-if="formType === 'subdomain'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Scanner de Subdomínios</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Domínio Alvo</label>
                            <input type="text" v-model="scanParams.target" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="exemplo.com">
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Método</label>
                            <select v-model="scanParams.method" 
                                    class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary">
                                <option value="bruteforce">Força Bruta</option>
                                <option value="passive">Passivo</option>
                            </select>
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-play mr-2"></i> Iniciar Scan
                        </button>
                    </form>
                </div>
                
                <!-- Formulário de Scanner de Tecnologias -->
                <div v-if="formType === 'tech'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Scanner de Tecnologias</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">URL Alvo</label>
                            <input type="text" v-model="scanParams.target" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="https://exemplo.com">
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-play mr-2"></i> Iniciar Scan
                        </button>
                    </form>
                </div>
                
                <!-- Formulário de Scanner de Plugins -->
                <div v-if="formType === 'plugin'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Scanner de Plugins</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">URL Alvo</label>
                            <input type="text" v-model="scanParams.target" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="https://exemplo.com">
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">CMS</label>
                            <select v-model="scanParams.cms" 
                                    class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary">
                                <option value="wordpress">WordPress</option>
                                <option value="joomla">Joomla</option>
                                <option value="drupal">Drupal</option>
                            </select>
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-play mr-2"></i> Iniciar Scan
                        </button>
                    </form>
                </div>
                
                <!-- Formulário de Scanner SQL Injection -->
                <div v-if="formType === 'sqli'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Scanner de SQL Injection</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">URL Alvo</label>
                            <input type="text" v-model="scanParams.target" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="https://exemplo.com/page.php?id=1">
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Parâmetros (opcional)</label>
                            <input type="text" v-model="scanParams.params" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="id,page,user (separados por vírgula)">
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-play mr-2"></i> Iniciar Scan
                        </button>
                    </form>
                </div>
                
                <!-- Formulário de Scanner XSS -->
                <div v-if="formType === 'xss'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Scanner de XSS</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">URL Alvo</label>
                            <input type="text" v-model="scanParams.target" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="https://exemplo.com/page.php?search=test">
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Parâmetros (opcional)</label>
                            <input type="text" v-model="scanParams.params" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="search,q,query (separados por vírgula)">
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-play mr-2"></i> Iniciar Scan
                        </button>
                    </form>
                </div>
                
                <!-- Formulário de Scanner Open Redirect -->
                <div v-if="formType === 'redirect'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Scanner de Open Redirect</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">URL Alvo</label>
                            <input type="text" v-model="scanParams.target" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="https://exemplo.com/redirect?url=test">
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Parâmetros (opcional)</label>
                            <input type="text" v-model="scanParams.params" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="url,redirect,goto (separados por vírgula)">
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-play mr-2"></i> Iniciar Scan
                        </button>
                    </form>
                </div>
                
                <!-- Formulário de Brute Force -->
                <div v-if="formType === 'bruteforce'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Brute Force</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">URL Alvo</label>
                            <input type="text" v-model="scanParams.target" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="https://exemplo.com/login.php">
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Modo</label>
                            <select v-model="scanParams.mode" 
                                    class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary">
                                <option value="login">Formulário de Login</option>
                                <option value="form">Formulário Personalizado</option>
                                <option value="basic_auth">Autenticação Básica</option>
                            </select>
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Usuários (um por linha)</label>
                            <textarea v-model="scanParams.usernameList" 
                                     class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                     rows="3" placeholder="admin&#10;administrator&#10;root"></textarea>
                        </div>
                        
                                                <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Senhas (uma por linha)</label>
                            <textarea v-model="scanParams.passwordList" 
                                     class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                     rows="3" placeholder="password&#10;123456&#10;admin"></textarea>
                        </div>
                        
                        <div v-if="scanParams.mode === 'form'" class="mb-4">
                            <label class="block text-gray-300 mb-2">Campo de Usuário</label>
                            <input type="text" v-model="scanParams.usernameField" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="username">
                                   
                            <label class="block text-gray-300 mb-2 mt-3">Campo de Senha</label>
                            <input type="text" v-model="scanParams.passwordField" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="password">
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-play mr-2"></i> Iniciar Brute Force
                        </button>
                    </form>
                </div>
                
                <!-- Formulário de Bypass 403 -->
                <div v-if="formType === 'bypass-403'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Bypass 403</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">URL Alvo</label>
                            <input type="text" v-model="scanParams.target" 
                                   class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                   placeholder="https://exemplo.com/admin">
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Técnicas</label>
                            <div class="space-y-2">
                                <div class="flex items-center">
                                    <input type="checkbox" id="headers" value="headers" v-model="scanParams.techniques" class="mr-2">
                                    <label for="headers" class="text-gray-300">Headers</label>
                                </div>
                                <div class="flex items-center">
                                    <input type="checkbox" id="paths" value="paths" v-model="scanParams.techniques" class="mr-2">
                                    <label for="paths" class="text-gray-300">Paths</label>
                                </div>
                                <div class="flex items-center">
                                    <input type="checkbox" id="methods" value="methods" v-model="scanParams.techniques" class="mr-2">
                                    <label for="methods" class="text-gray-300">Métodos HTTP</label>
                                </div>
                            </div>
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-play mr-2"></i> Iniciar Bypass
                        </button>
                    </form>
                </div>
                
                <!-- Analisador de Hash -->
                <div v-if="formType === 'hash'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Analisador de Hash</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Valor do Hash</label>
                            <textarea v-model="scanParams.hashValue" 
                                     class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                     placeholder="Hash para análise (ex: 5f4dcc3b5aa765d61d8327deb882cf99)" rows="3"></textarea>
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-search mr-2"></i> Analisar Hash
                        </button>
                    </form>
                    
                    <div class="mt-4 border-t border-gray-800 pt-4">
                        <h4 class="text-md font-semibold mb-3 text-primary">Gerador de Hash</h4>
                        
                        <form @submit.prevent="generateHash">
                            <div class="mb-4">
                                <label class="block text-gray-300 mb-2">Texto para gerar hash</label>
                                <input type="text" v-model="scanParams.inputString" 
                                       class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                       placeholder="Texto para gerar hash">
                            </div>
                            
                            <div class="mb-4">
                                <label class="block text-gray-300 mb-2">Algoritmos</label>
                                <div class="grid grid-cols-2 gap-2">
                                    <div v-for="algo in $parent.hashAlgorithms" :key="algo.value" class="flex items-center">
                                        <input type="checkbox" :id="algo.value" v-model="scanParams.selectedAlgorithms" :value="algo.value" class="mr-2">
                                        <label :for="algo.value" class="text-gray-300 text-sm">{{ algo.name }}</label>
                                    </div>
                                </div>
                            </div>
                            
                            <button type="submit" 
                                    class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                    :disabled="isLoading || !scanParams.inputString">
                                <i class="fas fa-cog mr-2"></i> Gerar Hash
                            </button>
                        </form>
                    </div>
                </div>
                
                <!-- Quebra de Criptografia -->
                <div v-if="formType === 'crypto'">
                    <h3 class="text-lg font-semibold mb-4 text-primary">Quebra de Criptografia</h3>
                    
                    <form @submit.prevent="submitForm">
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Valor do Hash</label>
                            <textarea v-model="scanParams.hashValue" 
                                     class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                     placeholder="Hash para quebrar" rows="3"></textarea>
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Tipo do Hash</label>
                            <select v-model="scanParams.hashType" 
                                    class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary">
                                <option value="md5">MD5</option>
                                <option value="sha1">SHA-1</option>
                                <option value="sha256">SHA-256</option>
                                <option value="ntlm">NTLM</option>
                            </select>
                        </div>
                        
                        <div class="mb-4">
                            <label class="block text-gray-300 mb-2">Wordlist</label>
                            <select v-model="scanParams.wordlist" 
                                    class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary">
                                <option value="common">Comum (100 palavras)</option>
                                <option value="passwords">Senhas Comuns (1000 palavras)</option>
                                <option value="custom">Personalizada</option>
                            </select>
                        </div>
                        
                        <div class="mb-4" v-if="scanParams.wordlist === 'custom'">
                            <label class="block text-gray-300 mb-2">Lista Personalizada</label>
                            <textarea v-model="scanParams.customWordlist" 
                                     class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                     placeholder="Uma palavra por linha" rows="5"></textarea>
                        </div>
                        
                        <button type="submit" 
                                class="w-full bg-primary hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-hammer mr-2"></i> Quebrar Hash
                        </button>
                        
                        <button type="button" @click="estimateTime" 
                                class="w-full mt-2 bg-gray-700 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                :disabled="isLoading">
                            <i class="fas fa-clock mr-2"></i> Estimar Tempo
                        </button>
                    </form>
                    
                    <div class="mt-4 border-t border-gray-800 pt-4">
                        <h4 class="text-md font-semibold mb-3 text-primary">Decodificador</h4>
                        
                        <form @submit.prevent="decodeString">
                            <div class="mb-4">
                                <label class="block text-gray-300 mb-2">Texto Codificado</label>
                                <textarea v-model="scanParams.encodedString" 
                                         class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                         placeholder="Texto codificado para decodificar" rows="3"></textarea>
                            </div>
                            
                            <div class="mb-4">
                                <label class="block text-gray-300 mb-2">Tipo de Codificação</label>
                                <select v-model="scanParams.encodingType" 
                                        class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary">
                                    <option value="base64">Base64</option>
                                    <option value="hex">Hexadecimal</option>
                                    <option value="binary">Binário</option>
                                    <option value="caesar">Cifra de César</option>
                                </select>
                            </div>
                            
                            <div class="mb-4" v-if="scanParams.encodingType === 'caesar'">
                                <label class="block text-gray-300 mb-2">Deslocamento (opcional)</label>
                                <input type="number" v-model="scanParams.shift" min="1" max="25"
                                       class="w-full bg-dark text-white border border-gray-700 rounded px-3 py-2 focus:outline-none focus:border-primary"
                                       placeholder="1-25 (deixe vazio para testar todos)">
                            </div>
                            
                            <button type="submit" 
                                    class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded focus:outline-none"
                                    :disabled="isLoading || !scanParams.encodedString">
                                <i class="fas fa-unlock mr-2"></i> Decodificar
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    `
});