// Configurações da API
const API_URL = 'http://localhost:5000/api';
const PHP_API_URL = 'server/api';

// Aplicação Vue
const app = Vue.createApp({
    data() {
        return {
            // Estado da UI
            currentTool: 'port-scanner',
            isLoading: false,
            isAuthenticated: false,
            user: null,
            isSidebarOpen: true,
            showLoginModal: false,
            showRegisterModal: false,
            loginError: null,
            registerError: null,

            // Formulários de autenticação
            loginForm: {
                username: '',
                password: ''
            },
            registerForm: {
                username: '',
                email: '',
                password: '',
                confirmPassword: ''
            },

            // Port Scanner
            portScanner: {
                target: '',
                portRange: '1-1000',
                results: null
            },

            // Directory Scanner
            directoryScanner: {
                target: '',
                wordlist: 'common',
                extensions: 'php,html,js,txt',
                results: null
            },

            // Subdomain Scanner
            subdomainScanner: {
                target: '',
                method: 'bruteforce',
                results: null
            },

            // Tech Scanner
            techScanner: {
                target: '',
                results: null
            },

            // Plugin Scanner
            pluginScanner: {
                target: '',
                cms: 'wordpress',
                results: null
            },

            // SQLi Scanner
            sqliScanner: {
                target: '',
                params: '',
                results: null
            },

            // XSS Scanner
            xssScanner: {
                target: '',
                params: '',
                results: null
            },

            // Redirect Scanner
            redirectScanner: {
                target: '',
                params: '',
                results: null
            },

            // Brute Force
            bruteForce: {
                target: '',
                mode: 'login',
                usernameList: 'admin\nadministrator\nroot',
                passwordList: 'password\n123456\nadmin',
                usernameField: 'username',
                passwordField: 'password',
                results: null
            },

            // Bypass 403
            bypass403: {
                target: '',
                techniques: ['headers', 'paths', 'methods'],
                results: null
            },

            // Analisador de Hash
            hashAnalyzer: {
                hashValue: '',
                inputString: '',
                selectedAlgorithms: ['md5', 'sha1', 'sha256'],
                results: null,
                mode: 'analyze' // 'analyze' ou 'generate'
            },

            // Quebra de Criptografia
            cryptoCracker: {
                hashValue: '',
                hashType: 'md5',
                wordlist: 'common',
                customWordlist: '',
                encodedString: '',
                encodingType: 'base64',
                shift: null,
                results: null,
                mode: 'crack' // 'crack', 'decode' ou 'estimate'
            },

            // Gerador de Relatórios
            reportGenerator: {
                title: 'NSF Security Report',
                companyName: '',
                author: '',
                format: 'markdown',
                selectedResults: [],
                result: null
            },

            // Resultados salvos
            savedResults: [],

            // Lista de algoritmos de hash disponíveis
            hashAlgorithms: [
                { name: 'MD5', value: 'md5' },
                { name: 'SHA-1', value: 'sha1' },
                { name: 'SHA-256', value: 'sha256' },
                { name: 'SHA-512', value: 'sha512' },
                { name: 'SHA3-224', value: 'sha3_224' },
                { name: 'SHA3-256', value: 'sha3_256' },
                { name: 'SHA3-384', value: 'sha3_384' },
                { name: 'SHA3-512', value: 'sha3_512' }
            ]
        }
    },

    computed: {
        // Título da ferramenta atual
        toolTitle() {
            const titles = {
                'port-scanner': 'Scanner de Portas',
                'directory-scanner': 'Scanner de Diretórios',
                'subdomain-scanner': 'Scanner de Subdomínios',
                'tech-scanner': 'Scanner de Tecnologias',
                'plugin-scanner': 'Scanner de Plugins',
                'sqli-scanner': 'Scanner de SQL Injection',
                'xss-scanner': 'Scanner de XSS',
                'redirect-scanner': 'Scanner de Open Redirect',
                'bruteforce': 'Brute Force',
                'bypass-403': 'Bypass 403',
                'hash-analyzer': 'Analisador de Hash',
                'crypto-cracker': 'Quebra de Criptografia',
                'report-generator': 'Gerador de Relatórios',
                'history': 'Histórico de Scans'
            };

            return titles[this.currentTool] || 'NSF';
        },

        // Descrição da ferramenta atual
        toolDescription() {
            const descriptions = {
                'port-scanner': 'Encontre portas abertas em um host ou domínio',
                'directory-scanner': 'Descubra diretórios e arquivos ocultos em um site',
                'subdomain-scanner': 'Encontre subdomínios em um domínio',
                'tech-scanner': 'Identifique tecnologias utilizadas em um site',
                'plugin-scanner': 'Descubra plugins instalados em CMS como WordPress',
                'sqli-scanner': 'Encontre vulnerabilidades de SQL Injection',
                'xss-scanner': 'Encontre vulnerabilidades de Cross-Site Scripting',
                'redirect-scanner': 'Encontre vulnerabilidades de Open Redirect',
                'bruteforce': 'Realize ataques de força bruta em formulários de login',
                'bypass-403': 'Tente contornar páginas protegidas (403 Forbidden)',
                'hash-analyzer': 'Analise e identifique tipos de hash, gere hashes a partir de texto',
                'crypto-cracker': 'Tente quebrar hashes e decodificar textos codificados',
                'report-generator': 'Gere relatórios detalhados dos seus scans',
                'history': 'Visualize o histórico de scans realizados'
            };

            return descriptions[this.currentTool] || '';
        },

        // Ícone da ferramenta atual
        toolIcon() {
            const icons = {
                'port-scanner': 'fas fa-network-wired',
                'directory-scanner': 'fas fa-folder-open',
                'subdomain-scanner': 'fas fa-globe',
                'tech-scanner': 'fas fa-code',
                'plugin-scanner': 'fas fa-puzzle-piece',
                'sqli-scanner': 'fas fa-database',
                'xss-scanner': 'fas fa-code',
                'redirect-scanner': 'fas fa-external-link-alt',
                'bruteforce': 'fas fa-hammer',
                'bypass-403': 'fas fa-unlock-alt',
                'hash-analyzer': 'fas fa-fingerprint',
                'crypto-cracker': 'fas fa-unlock-alt',
                'report-generator': 'fas fa-file-alt',
                'history': 'fas fa-history'
            };

            return icons[this.currentTool] || 'fas fa-shield-alt';
        }
    },

    mounted() {
        // Carregar resultados salvos do localStorage
        this.loadSavedResults();

        // Verificar se o usuário está autenticado
        this.checkAuth();

        // Verificar preferência do sidebar
        const sidebarPref = localStorage.getItem('sidebar_open');
        if (sidebarPref !== null) {
            this.isSidebarOpen = sidebarPref === 'true';
        }
    },

    methods: {
        // Mudar ferramenta atual
        changeTool(tool) {
            this.currentTool = tool;
        },

        // Toggle da sidebar
        toggleSidebar() {
            this.isSidebarOpen = !this.isSidebarOpen;
            localStorage.setItem('sidebar_open', this.isSidebarOpen);
        },

        // Checar autenticação
        async checkAuth() {
            try {
                const response = await axios.get(`${PHP_API_URL}/users.php?action=check`, {
                    withCredentials: true
                });

                if (response.data.authenticated) {
                    this.isAuthenticated = true;
                    this.user = response.data.user;
                }
            } catch (error) {
                console.error('Erro ao verificar autenticação:', error);
            }
        },

        // Login
        async login() {
            this.loginError = null;

            if (!this.loginForm.username || !this.loginForm.password) {
                this.loginError = 'Preencha todos os campos';
                return;
            }

            this.isLoading = true;

            try {
                const response = await axios.post(`${PHP_API_URL}/users.php?action=login`, this.loginForm);

                if (response.data.success) {
                    this.isAuthenticated = true;
                    this.user = response.data.user;
                    this.showLoginModal = false;

                    // Limpar formulário
                    this.loginForm = {
                        username: '',
                        password: ''
                    };
                } else {
                    this.loginError = response.data.message || 'Erro ao fazer login';
                }
            } catch (error) {
                console.error('Erro de login:', error);
                this.loginError = 'Erro ao conectar com o servidor';
            } finally {
                this.isLoading = false;
            }
        },

        // Registro
        async register() {
            this.registerError = null;

            // Validar campos
            if (!this.registerForm.username || !this.registerForm.email ||
                !this.registerForm.password || !this.registerForm.confirmPassword) {
                this.registerError = 'Preencha todos os campos';
                return;
            }

            if (this.registerForm.password !== this.registerForm.confirmPassword) {
                this.registerError = 'As senhas não coincidem';
                return;
            }

            this.isLoading = true;

            try {
                const response = await axios.post(`${PHP_API_URL}/users.php?action=register`, this.registerForm);

                if (response.data.success) {
                    alert('Registro realizado com sucesso! Faça login para continuar.');
                    this.showRegisterModal = false;
                    this.showLoginModal = true;

                    // Limpar formulário
                    this.registerForm = {
                        username: '',
                        email: '',
                        password: '',
                        confirmPassword: ''
                    };
                } else {
                    this.registerError = response.data.message || 'Erro ao registrar';
                }
            } catch (error) {
                console.error('Erro de registro:', error);
                this.registerError = 'Erro ao conectar com o servidor';
            } finally {
                this.isLoading = false;
            }
        },

        // Logout
        async logout() {
            try {
                await axios.post(`${PHP_API_URL}/users.php?action=logout`);
                this.isAuthenticated = false;
                this.user = null;
            } catch (error) {
                console.error('Erro ao fazer logout:', error);
            }
        },

        // Scanner de Portas
        async runPortScan() {
            if (!this.portScanner.target) {
                alert('Por favor, insira um alvo válido!');
                return;
            }

            this.isLoading = true;

            try {
                const response = await axios.post(`${API_URL}/scan/ports`, {
                    target: this.portScanner.target,
                    port_range: this.portScanner.portRange
                });

                this.portScanner.results = response.data;
            } catch (error) {
                console.error('Erro ao realizar scan de portas:', error);
                alert(`Erro: ${error.response?.data?.error || 'Falha na conexão com o servidor'}`);
            } finally {
                this.isLoading = false;
            }
        },

        // Scanner de Diretórios
        async runDirectoryScan() {
            if (!this.directoryScanner.target) {
                alert('Por favor, insira uma URL alvo válida!');
                return;
            }

            this.isLoading = true;

            try {
                const extensions = this.directoryScanner.extensions.split(',')
                    .map(ext => ext.trim())
                    .filter(ext => ext);

                const response = await axios.post(`${API_URL}/scan/directories`, {
                    target: this.directoryScanner.target,
                    wordlist: this.directoryScanner.wordlist,
                    extensions: extensions
                });

                this.directoryScanner.results = response.data;
            } catch (error) {
                console.error('Erro ao realizar scan de diretórios:', error);
                alert(`Erro: ${error.response?.data?.error || 'Falha na conexão com o servidor'}`);
            } finally {
                this.isLoading = false;
            }
        },

        // Scanner de Subdomínios
        async runSubdomainScan() {
            if (!this.subdomainScanner.target) {
                alert('Por favor, insira um domínio alvo válido!');
                return;
            }

            this.isLoading = true;

            try {
                const response = await axios.post(`${API_URL}/scan/subdomains`, {
                    target: this.subdomainScanner.target,
                    method: this.subdomainScanner.method
                });

                this.subdomainScanner.results = response.data;
            } catch (error) {
                console.error('Erro ao realizar scan de subdomínios:', error);
                alert(`Erro: ${error.response?.data?.error || 'Falha na conexão com o servidor'}`);
            } finally {
                this.isLoading = false;
            }
        },

        // Salvar resultados
        saveResults() {
            let currentResults = null;
            let scanType = '';

            switch (this.currentTool) {
                case 'port-scanner':
                    currentResults = this.portScanner.results;
                    scanType = 'port_scan';
                    break;
                case 'directory-scanner':
                    currentResults = this.directoryScanner.results;
                    scanType = 'directory_scan';
                    break;
                case 'subdomain-scanner':
                    currentResults = this.subdomainScanner.results;
                    scanType = 'subdomain_scan';
                    break;
                case 'tech-scanner':
                    currentResults = this.techScanner.results;
                    scanType = 'tech_scan';
                    break;
                case 'plugin-scanner':
                    currentResults = this.pluginScanner.results;
                    scanType = 'plugin_scan';
                    break;
                case 'sqli-scanner':
                    currentResults = this.sqliScanner.results;
                    scanType = 'sqli_scan';
                    break;
                case 'xss-scanner':
                    currentResults = this.xssScanner.results;
                    scanType = 'xss_scan';
                    break;
                case 'redirect-scanner':
                    currentResults = this.redirectScanner.results;
                    scanType = 'redirect_scan';
                    break;
                case 'bruteforce':
                    currentResults = this.bruteForce.results;
                    scanType = 'bruteforce';
                    break;
                case 'bypass-403':
                    currentResults = this.bypass403.results;
                    scanType = 'bypass_403';
                    break;
                case 'hash-analyzer':
                    currentResults = this.hashAnalyzer.results;
                    scanType = this.hashAnalyzer.mode === 'analyze' ? 'hash_analyze' : 'hash_generate';
                    break;
                case 'crypto-cracker':
                    currentResults = this.cryptoCracker.results;
                    scanType = this.cryptoCracker.mode === 'crack' ? 'crypto_crack' :
                        this.cryptoCracker.mode === 'decode' ? 'crypto_decode' : 'crypto_estimate';
                    break;
            }

            if (currentResults) {
                // Adicionar tipo de scan aos resultados
                const resultsToSave = JSON.parse(JSON.stringify(currentResults));
                resultsToSave.scan_type = scanType;

                this.savedResults.push(resultsToSave);
                this.saveSavedResultsToStorage();
                this.showNotification('success', 'Resultados salvos com sucesso!');
            }
        },

        // Limpar resultados
        clearResults() {
            switch (this.currentTool) {
                case 'port-scanner':
                    this.portScanner.results = null;
                    break;
                case 'directory-scanner':
                    this.directoryScanner.results = null;
                    break;
                case 'subdomain-scanner':
                    this.subdomainScanner.results = null;
                    break;
                case 'tech-scanner':
                    this.techScanner.results = null;
                    break;
                case 'plugin-scanner':
                    this.pluginScanner.results = null;
                    break;
                case 'sqli-scanner':
                    this.sqliScanner.results = null;
                    break;
                case 'xss-scanner':
                    this.xssScanner.results = null;
                    break;
                case 'redirect-scanner':
                    this.redirectScanner.results = null;
                    break;
                case 'bruteforce':
                    this.bruteForce.results = null;
                    break;
                case 'bypass-403':
                    this.bypass403.results = null;
                    break;
                case 'hash-analyzer':
                    this.hashAnalyzer.results = null;
                    break;
                case 'crypto-cracker':
                    this.cryptoCracker.results = null;
                    break;
            }

            this.showNotification('info', 'Resultados limpos!');
        },

        // Salvar resultados no localStorage
        saveSavedResultsToStorage() {
            localStorage.setItem('nsf_saved_results', JSON.stringify(this.savedResults));
        },

        // Carregar resultados do localStorage
        loadSavedResults() {
            const savedData = localStorage.getItem('nsf_saved_results');
            if (savedData) {
                try {
                    this.savedResults = JSON.parse(savedData);
                } catch (e) {
                    console.error('Erro ao carregar resultados salvos:', e);
                    this.savedResults = [];
                }
            }
        },

        // Remover um resultado salvo
        removeResult(index) {
            if (confirm('Tem certeza que deseja remover este resultado?')) {
                this.savedResults.splice(index, 1);
                this.saveSavedResultsToStorage();
                this.showNotification('info', 'Resultado removido!');
            }
        },

        // Visualizar um resultado salvo
        viewResult(result) {
            // Determinar qual ferramenta deve exibir o resultado
            const toolMap = {
                'port_scan': 'port-scanner',
                'directory_scan': 'directory-scanner',
                'subdomain_scan': 'subdomain-scanner',
                'tech_scan': 'tech-scanner',
                'plugin_scan': 'plugin-scanner',
                'sqli_scan': 'sqli-scanner',
                'xss_scan': 'xss-scanner',
                'redirect_scan': 'redirect-scanner',
                'bruteforce': 'bruteforce',
                'bypass_403': 'bypass-403',
                'hash_analyze': 'hash-analyzer',
                'hash_generate': 'hash-analyzer',
                'crypto_crack': 'crypto-cracker',
                'crypto_decode': 'crypto-cracker',
                'crypto_estimate': 'crypto-cracker'
            };

            const targetTool = toolMap[result.scan_type];
            if (!targetTool) return;

            // Mudar para a ferramenta correta
            this.changeTool(targetTool);

            // Atribuir o resultado à ferramenta correta
            switch (targetTool) {
                case 'port-scanner':
                    this.portScanner.results = result;
                    break;
                case 'directory-scanner':
                    this.directoryScanner.results = result;
                    break;
                case 'subdomain-scanner':
                    this.subdomainScanner.results = result;
                    break;
                case 'tech-scanner':
                    this.techScanner.results = result;
                    break;
                case 'plugin-scanner':
                    this.pluginScanner.results = result;
                    break;
                case 'sqli-scanner':
                    this.sqliScanner.results = result;
                    break;
                case 'xss-scanner':
                    this.xssScanner.results = result;
                    break;
                case 'redirect-scanner':
                    this.redirectScanner.results = result;
                    break;
                case 'bruteforce':
                    this.bruteForce.results = result;
                    break;
                case 'bypass-403':
                    this.bypass403.results = result;
                    break;
                case 'hash-analyzer':
                    this.hashAnalyzer.results = result;
                    this.hashAnalyzer.mode = result.scan_type === 'hash_analyze' ? 'analyze' : 'generate';
                    break;
                case 'crypto-cracker':
                    this.cryptoCracker.results = result;
                    if (result.scan_type === 'crypto_crack') {
                        this.cryptoCracker.mode = 'crack';
                    } else if (result.scan_type === 'crypto_decode') {
                        this.cryptoCracker.mode = 'decode';
                    } else {
                        this.cryptoCracker.mode = 'estimate';
                    }
                    break;
            }
        },

        // Analisador de Hash
        async analyzeHash() {
            if (!this.hashAnalyzer.hashValue) {
                alert('Por favor, insira um valor de hash para análise!');
                return;
            }

            this.isLoading = true;
            this.hashAnalyzer.mode = 'analyze';

            try {
                const response = await axios.post(`${API_URL}/analyze/hash`, {
                    hash_value: this.hashAnalyzer.hashValue
                });

                this.hashAnalyzer.results = response.data;
            } catch (error) {
                console.error('Erro ao analisar hash:', error);
                alert(`Erro: ${error.response?.data?.error || 'Falha na conexão com o servidor'}`);
            } finally {
                this.isLoading = false;
            }
        },

        async generateHash() {
            if (!this.hashAnalyzer.inputString) {
                alert('Por favor, insira um texto para gerar hash!');
                return;
            }

            if (this.hashAnalyzer.selectedAlgorithms.length === 0) {
                alert('Por favor, selecione pelo menos um algoritmo de hash!');
                return;
            }

            this.isLoading = true;
            this.hashAnalyzer.mode = 'generate';

            try {
                const response = await axios.post(`${API_URL}/analyze/hash/generate`, {
                    input: this.hashAnalyzer.inputString,
                    algorithms: this.hashAnalyzer.selectedAlgorithms
                });

                this.hashAnalyzer.results = response.data;
            } catch (error) {
                console.error('Erro ao gerar hash:', error);
                alert(`Erro: ${error.response?.data?.error || 'Falha na conexão com o servidor'}`);
            } finally {
                this.isLoading = false;
            }
        },

        // Quebra de Hash
        async crackHash() {
            if (!this.cryptoCracker.hashValue) {
                alert('Por favor, insira um hash para quebrar!');
                return;
            }

            this.isLoading = true;
            this.cryptoCracker.mode = 'crack';

            try {
                // Preparar a wordlist
                let wordlist = this.cryptoCracker.wordlist;

                // Se for uma wordlist personalizada, criar um array de palavras
                if (this.cryptoCracker.wordlist === 'custom' && this.cryptoCracker.customWordlist) {
                    wordlist = this.cryptoCracker.customWordlist.split('\n').filter(word => word.trim());
                }

                const response = await axios.post(`${API_URL}/crack/hash`, {
                    hash_value: this.cryptoCracker.hashValue,
                    hash_type: this.cryptoCracker.hashType,
                    wordlist: wordlist
                });

                this.cryptoCracker.results = response.data;
            } catch (error) {
                console.error('Erro ao quebrar hash:', error);
                alert(`Erro: ${error.response?.data?.error || 'Falha na conexão com o servidor'}`);
            } finally {
                this.isLoading = false;
            }
        },

        async decodeString() {
            if (!this.cryptoCracker.encodedString) {
                alert('Por favor, insira um texto codificado para decodificar!');
                return;
            }

            this.isLoading = true;
            this.cryptoCracker.mode = 'decode';

            try {
                const payload = {
                    encoded_string: this.cryptoCracker.encodedString,
                    encoding_type: this.cryptoCracker.encodingType
                };

                // Adicionar o deslocamento para cifra de César se fornecido
                if (this.cryptoCracker.encodingType === 'caesar' && this.cryptoCracker.shift) {
                    payload.shift = parseInt(this.cryptoCracker.shift);
                }

                const response = await axios.post(`${API_URL}/crack/decode`, payload);

                this.cryptoCracker.results = response.data;
            } catch (error) {
                console.error('Erro ao decodificar string:', error);
                alert(`Erro: ${error.response?.data?.error || 'Falha na conexão com o servidor'}`);
            } finally {
                this.isLoading = false;
            }
        },

        async estimateCrackTime() {
            if (!this.cryptoCracker.hashType) {
                alert('Por favor, selecione um tipo de hash!');
                return;
            }

            this.isLoading = true;
            this.cryptoCracker.mode = 'estimate';

            try {
                // Estimar o tamanho da wordlist
                let wordlistSize = 10000; // Tamanho padrão

                if (this.cryptoCracker.wordlist === 'common') {
                    wordlistSize = 100;
                } else if (this.cryptoCracker.wordlist === 'passwords') {
                    wordlistSize = 1000;
                } else if (this.cryptoCracker.wordlist === 'custom' && this.cryptoCracker.customWordlist) {
                    wordlistSize = this.cryptoCracker.customWordlist.split('\n').filter(word => word.trim()).length;
                }

                const response = await axios.post(`${API_URL}/crack/estimate`, {
                    hash_type: this.cryptoCracker.hashType,
                    wordlist_size: wordlistSize
                });

                this.cryptoCracker.results = response.data;
            } catch (error) {
                console.error('Erro ao estimar tempo de quebra:', error);
                alert(`Erro: ${error.response?.data?.error || 'Falha na conexão com o servidor'}`);
            } finally {
                this.isLoading = false;
            }
        },

        // Gerador de Relatórios
        async generateReport() {
            if (this.reportGenerator.selectedResults.length === 0) {
                alert('Por favor, selecione pelo menos um resultado para incluir no relatório!');
                return;
            }

            this.isLoading = true;

            try {
                // Obter os resultados selecionados
                const selectedResults = this.reportGenerator.selectedResults.map(index => this.savedResults[index]);

                const response = await axios.post(`${API_URL}/report/generate`, {
                    scan_results: selectedResults,
                    format: this.reportGenerator.format,
                    title: this.reportGenerator.title,
                    company_name: this.reportGenerator.companyName,
                    author: this.reportGenerator.author
                });

                this.reportGenerator.result = response.data;
                this.showNotification('success', 'Relatório gerado com sucesso!');
            } catch (error) {
                console.error('Erro ao gerar relatório:', error);
                alert(`Erro: ${error.response?.data?.error || 'Falha na conexão com o servidor'}`);
            } finally {
                this.isLoading = false;
            }
        },

        // Download do relatório
        downloadReport() {
            if (!this.reportGenerator.result) return;

            if (this.reportGenerator.format === 'markdown') {
                // Download de arquivo Markdown
                const blob = new Blob([this.reportGenerator.result.content], { type: 'text/markdown' });
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');

                const fileName = `nsf_report_${new Date().toISOString().slice(0, 10)}.md`;

                link.href = url;
                link.download = fileName;
                link.click();

                URL.revokeObjectURL(url);
                this.showNotification('success', `Relatório ${fileName} baixado com sucesso!`);
            } else if (this.reportGenerator.format === 'pdf') {
                // Para PDF, precisamos fazer uma requisição ao servidor PHP para obter o arquivo
                const filePath = this.reportGenerator.result.file_path;
                window.open(`${PHP_API_URL}/reports.php?action=download&file=${encodeURIComponent(filePath)}`, '_blank');
                this.showNotification('success', 'Download do PDF iniciado!');
            }
        },

        // Função para copiar para o clipboard
        copyToClipboard(text) {
            navigator.clipboard.writeText(text)
                .then(() => {
                    this.showNotification('success', 'Copiado para a área de transferência!');
                })
                .catch(err => {
                    console.error('Erro ao copiar para o clipboard:', err);
                    alert('Não foi possível copiar para a área de transferência');
                });
        },

        // Mostrar notificação
        showNotification(type, message) {
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                    <div class="flex items-center">
                        <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'error' ? 'fa-exclamation-circle' : 'fa-info-circle'} mr-2"></i>
                        <span>${message}</span>
                    </div>
                `;

            document.body.appendChild(notification);

            // Mostrar com animação
            setTimeout(() => {
                notification.classList.add('show');
            }, 10);

            // Remover após 3 segundos
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => {
                    notification.remove();
                }, 300);
            }, 3000);
        },

        // Utilitários
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
                'hash_generate': 'Geração de Hash',
                'crypto_crack': 'Quebra de Hash',
                'crypto_decode': 'Decodificação',
                'crypto_estimate': 'Estimativa de Quebra'
            };

            return types[type] || type.replace('_', ' ').toUpperCase();
        },

        formatTimestamp(timestamp) {
            if (!timestamp) return '';
            const date = new Date(timestamp);
            return date.toLocaleString();
        },

        getTypeClass(type) {
            const classes = {
                'port_scan': 'bg-blue-100 text-blue-800',
                'directory_scan': 'bg-green-100 text-green-800',
                'subdomain_scan': 'bg-purple-100 text-purple-800',
                'tech_scan': 'bg-indigo-100 text-indigo-800',
                'plugin_scan': 'bg-yellow-100 text-yellow-800',
                'sqli_scan': 'bg-red-100 text-red-800',
                'xss_scan': 'bg-pink-100 text-pink-800',
                'redirect_scan': 'bg-orange-100 text-orange-800',
                'bruteforce': 'bg-gray-100 text-gray-800',
                'bypass_403': 'bg-teal-100 text-teal-800',
                'hash_analyze': 'bg-cyan-100 text-cyan-800',
                'hash_generate': 'bg-cyan-100 text-cyan-800',
                'crypto_crack': 'bg-amber-100 text-amber-800',
                'crypto_decode': 'bg-lime-100 text-lime-800',
                'crypto_estimate': 'bg-emerald-100 text-emerald-800'
            };

            return classes[type] || 'bg-gray-100 text-gray-800';
        },

        getSummary(result) {
            if (!result) return '';

            switch (result.scan_type) {
                case 'port_scan':
                    return `${result.total_open || 0} portas abertas`;
                case 'directory_scan':
                    return `${result.directories?.length || 0} diretórios`;
                case 'subdomain_scan':
                    return `${result.subdomains?.length || 0} subdomínios`;
                case 'tech_scan':
                    return `${result.technologies?.length || 0} tecnologias`;
                case 'plugin_scan':
                    return `${result.plugins?.length || 0} plugins`;
                case 'sqli_scan':
                case 'xss_scan':
                case 'redirect_scan':
                    return `${result.vulnerabilities?.filter(v => v.vulnerable).length || 0} vulnerabilidades`;
                case 'bruteforce':
                    return `${result.successful_attempts?.length || 0} credenciais`;
                case 'bypass_403':
                    return `${result.successful_techniques?.length || 0} técnicas`;
                default:
                    return 'Detalhes disponíveis';
            }
        }
    }
});

// Montar a aplicação Vue
app.mount('#app');