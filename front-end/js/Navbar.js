// Navbar.js - Componente da barra de navegação superior

// const app = Vue.createApp({});

app.component('navbar-component', {
    props: {
        user: {
            type: Object,
            default: null
        },
        isAuthenticated: {
            type: Boolean,
            default: false
        }
    },
    data() {
        return {
            showDropdown: false
        }
    },
    methods: {
        toggleDropdown() {
            this.showDropdown = !this.showDropdown;
        },
        handleLogout() {
            this.$emit('logout');
            this.showDropdown = false;
        },
        toggleSidebar() {
            this.$emit('toggle-sidebar');
        }
    },
    template: `
        <header class="bg-darkest text-white fixed top-0 left-0 right-0 z-10 shadow-md">
            <div class="container mx-auto px-4 py-3">
                <div class="flex justify-between items-center">
                    <!-- Logo e Botão do Menu-->
                    <div class="flex items-center space-x-4">
                        <button @click="toggleSidebar" class="focus:outline-none hover:text-primary transition duration-200">
                            <i class="fas fa-bars"></i>
                        </button>
                        <h1 class="text-2xl font-bold text-primary">
                            <i class="fas fa-shield-alt mr-2"></i> NSF
                        </h1>
                    </div>
                    
                    <!-- Menu do usuário -->
                    <div class="flex items-center space-x-2">
                        <template v-if="isAuthenticated">
                            <div class="relative">
                                <button @click="toggleDropdown" class="flex items-center space-x-2 focus:outline-none hover:text-primary transition duration-200">
                                    <span class="hidden md:inline-block">{{ user.username }}</span>
                                    <i class="fas fa-user-circle text-lg"></i>
                                    <i class="fas fa-angle-down"></i>
                                </button>
                                
                                <div v-if="showDropdown" class="absolute right-0 mt-2 w-48 bg-dark rounded-md shadow-lg py-1 z-10 border border-gray-700">
                                    <a href="#" class="block px-4 py-2 text-sm text-gray-300 hover:bg-gray-800 hover:text-white">
                                        <i class="fas fa-user mr-2"></i> Perfil
                                    </a>
                                    <a href="#" class="block px-4 py-2 text-sm text-gray-300 hover:bg-gray-800 hover:text-white">
                                        <i class="fas fa-cog mr-2"></i> Configurações
                                    </a>
                                    <div class="border-t border-gray-700 my-1"></div>
                                    <a href="#" @click.prevent="handleLogout" class="block px-4 py-2 text-sm text-red-400 hover:bg-gray-800">
                                        <i class="fas fa-sign-out-alt mr-2"></i> Sair
                                    </a>
                                </div>
                            </div>
                        </template>
                        <template v-else>
                            <button @click="$parent.showLoginModal = true" class="bg-primary hover:bg-blue-600 text-white py-1 px-3 rounded text-sm transition duration-200">
                                <i class="fas fa-sign-in-alt mr-1"></i> Login
                            </button>
                            <button @click="$parent.showRegisterModal = true" class="bg-darker hover:bg-gray-700 text-white py-1 px-3 rounded text-sm transition duration-200 border border-gray-700">
                                <i class="fas fa-user-plus mr-1"></i> Registrar
                            </button>
                        </template>
                    </div>
                </div>
            </div>
        </header>
    `
});