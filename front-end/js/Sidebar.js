// Sidebar.js - Componente da barra lateral

app.component('sidebar-component', {
    props: {
        currentTool: {
            type: String,
            required: true
        },
        isSidebarOpen: {
            type: Boolean,
            default: true
        }
    },
    methods: {
        changeTool(tool) {
            this.$emit('change-tool', tool);
        }
    },
    template: `
        <aside class="bg-darkest fixed left-0 top-16 bottom-0 transition-all duration-300 shadow-lg z-10 overflow-y-auto"
               :class="{'w-64': isSidebarOpen, 'w-16': !isSidebarOpen}">
            <div class="py-4">
                <!-- Grupos de ferramentas -->
                <div class="mb-6">
                    <div class="px-4 py-2 text-xs uppercase text-gray-500 font-semibold"
                         :class="{'text-center': !isSidebarOpen}">
                        <span v-if="isSidebarOpen">Ferramentas</span>
                        <span v-else><i class="fas fa-tools"></i></span>
                    </div>
                    
                    <!-- Itens de Reconhecimento -->
                    <a @click="changeTool('port-scanner')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'port-scanner'}">
                        <i class="fas fa-network-wired w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Scanner de Portas</span>
                    </a>
                    
                    <a @click="changeTool('directory-scanner')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'directory-scanner'}">
                        <i class="fas fa-folder-open w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Scanner de Diretórios</span>
                    </a>
                    
                    <a @click="changeTool('subdomain-scanner')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'subdomain-scanner'}">
                        <i class="fas fa-globe w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Scanner de Subdomínios</span>
                    </a>
                    
                    <a @click="changeTool('tech-scanner')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'tech-scanner'}">
                        <i class="fas fa-code w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Scanner de Tecnologias</span>
                    </a>
                    
                    <a @click="changeTool('plugin-scanner')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'plugin-scanner'}">
                        <i class="fas fa-puzzle-piece w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Scanner de Plugins</span>
                    </a>
                </div>
                
                <!-- Itens de Vulnerabilidades -->
                <div class="mb-6">
                    <div class="px-4 py-2 text-xs uppercase text-gray-500 font-semibold"
                         :class="{'text-center': !isSidebarOpen}">
                        <span v-if="isSidebarOpen">Vulnerabilidades</span>
                        <span v-else><i class="fas fa-bug"></i></span>
                    </div>
                    
                    <a @click="changeTool('sqli-scanner')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'sqli-scanner'}">
                        <i class="fas fa-database w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">SQL Injection</span>
                    </a>
                    
                    <a @click="changeTool('xss-scanner')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'xss-scanner'}">
                        <i class="fas fa-code w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">XSS</span>
                    </a>
                    
                    <a @click="changeTool('redirect-scanner')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'redirect-scanner'}">
                        <i class="fas fa-external-link-alt w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Open Redirect</span>
                    </a>
                    
                    <a @click="changeTool('bruteforce')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'bruteforce'}">
                        <i class="fas fa-hammer w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Brute Force</span>
                    </a>
                    
                    <a @click="changeTool('bypass-403')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'bypass-403'}">
                        <i class="fas fa-unlock-alt w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Bypass 403</span>
                    </a>
                </div>
                
                <!-- Itens de Criptografia -->
                <div class="mb-6">
                    <div class="px-4 py-2 text-xs uppercase text-gray-500 font-semibold"
                         :class="{'text-center': !isSidebarOpen}">
                        <span v-if="isSidebarOpen">Criptografia</span>
                        <span v-else><i class="fas fa-key"></i></span>
                    </div>
                    
                    <a @click="changeTool('hash-analyzer')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'hash-analyzer'}">
                        <i class="fas fa-fingerprint w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Analisador de Hash</span>
                    </a>
                    
                    <a @click="changeTool('crypto-cracker')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'crypto-cracker'}">
                        <i class="fas fa-unlock-alt w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Quebra de Criptografia</span>
                    </a>
                </div>
                
                <!-- Itens de Relatórios -->
                <div class="mb-6">
                    <div class="px-4 py-2 text-xs uppercase text-gray-500 font-semibold"
                         :class="{'text-center': !isSidebarOpen}">
                        <span v-if="isSidebarOpen">Relatórios</span>
                        <span v-else><i class="fas fa-file-alt"></i></span>
                    </div>
                    
                    <a @click="changeTool('report-generator')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'report-generator'}">
                        <i class="fas fa-file-alt w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Gerar Relatório</span>
                    </a>
                    
                    <a @click="changeTool('history')" 
                       class="flex items-center px-4 py-2 cursor-pointer transition-colors hover:bg-dark"
                       :class="{'justify-center': !isSidebarOpen, 'bg-dark text-primary': currentTool === 'history'}">
                        <i class="fas fa-history w-5 text-center"></i>
                        <span v-if="isSidebarOpen" class="ml-3">Histórico</span>
                    </a>
                </div>
            </div>
        </aside>
    `
});