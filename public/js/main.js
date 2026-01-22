// JavaScript principal para o sistema de gestão

// Funções globais
window.app = {
    // Configurações
    config: {
        apiBaseUrl: '/api',
        refreshInterval: 30000, // 30 segundos
        notificationDuration: 5000 // 5 segundos
    },

    loading: {
        show: function() {
            const el = document.getElementById('globalLoading');
            if (!el) return;
            el.classList.remove('d-none');
            el.setAttribute('aria-hidden', 'false');
        },
        hide: function() {
            const el = document.getElementById('globalLoading');
            if (!el) return;
            el.classList.add('d-none');
            el.setAttribute('aria-hidden', 'true');
        }
    },

    // Utilitários
    utils: {
        // Formatar data
        formatDate: function(date, format = 'DD/MM/YYYY') {
            return moment(date).format(format);
        },

        // Formatar dinheiro
        formatMoney: function(value) {
            return new Intl.NumberFormat('pt-BR', {
                style: 'currency',
                currency: 'BRL'
            }).format(value);
        },

        // Formatar telefone
        formatPhone: function(phone) {
            if (!phone) return '';
            
            // Remover tudo que não é dígito
            const cleaned = phone.replace(/\D/g, '');
            
            // Verificar se tem 11 dígitos (com 9) ou 10 (sem 9)
            if (cleaned.length === 11) {
                return `(${cleaned.slice(0, 2)}) ${cleaned.slice(2, 7)}-${cleaned.slice(7)}`;
            } else if (cleaned.length === 10) {
                return `(${cleaned.slice(0, 2)}) ${cleaned.slice(2, 6)}-${cleaned.slice(6)}`;
            }
            
            return phone;
        },

        // Formatar CPF
        formatCPF: function(cpf) {
            if (!cpf) return '';
            
            const cleaned = cpf.replace(/\D/g, '');
            
            if (cleaned.length === 11) {
                return `${cleaned.slice(0, 3)}.${cleaned.slice(3, 6)}.${cleaned.slice(6, 9)}-${cleaned.slice(9)}`;
            }
            
            return cpf;
        },

        // Validar CPF
        validateCPF: function(cpf) {
            if (!cpf) return false;
            
            const cleaned = cpf.replace(/\D/g, '');
            
            if (cleaned.length !== 11) return false;
            
            // Algoritmo de validação de CPF
            let sum = 0;
            let remainder;
            
            // Verificar CPFs inválidos conhecidos
            if (cleaned === '00000000000' || 
                cleaned === '11111111111' || 
                cleaned === '22222222222' || 
                cleaned === '33333333333' || 
                cleaned === '44444444444' || 
                cleaned === '55555555555' || 
                cleaned === '66666666666' || 
                cleaned === '77777777777' || 
                cleaned === '88888888888' || 
                cleaned === '99999999999') {
                return false;
            }
            
            // Primeiro dígito verificador
            for (let i = 1; i <= 9; i++) {
                sum = sum + parseInt(cleaned.substring(i - 1, i)) * (11 - i);
            }
            
            remainder = (sum * 10) % 11;
            
            if ((remainder === 10) || (remainder === 11)) {
                remainder = 0;
            }
            
            if (remainder !== parseInt(cleaned.substring(9, 10))) {
                return false;
            }
            
            // Segundo dígito verificador
            sum = 0;
            
            for (let i = 1; i <= 10; i++) {
                sum = sum + parseInt(cleaned.substring(i - 1, i)) * (12 - i);
            }
            
            remainder = (sum * 10) % 11;
            
            if ((remainder === 10) || (remainder === 11)) {
                remainder = 0;
            }
            
            if (remainder !== parseInt(cleaned.substring(10, 11))) {
                return false;
            }
            
            return true;
        },

        // Mostrar notificação
        showNotification: function(message, type, duration) {
            let bsType = type || 'info';
            if (bsType === 'error') bsType = 'danger';
            if (bsType === 'warn') bsType = 'warning';
            if (bsType === 'success' || bsType === 'info' || bsType === 'warning' || bsType === 'danger' || bsType === 'primary' || bsType === 'secondary' || bsType === 'light' || bsType === 'dark') {
                // ok
            } else {
                bsType = 'info';
            }
            const notification = document.createElement('div');
            notification.className = `alert alert-${bsType} alert-dismissible fade show position-fixed`;
            notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
            notification.innerHTML = `
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            
            document.body.appendChild(notification);
            
            // Auto remover após o tempo especificado
            const timeout = duration || app.config.notificationDuration;
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, timeout);
        },

        // Confirmar ação
        confirmAction: function(message, callback) {
            if (confirm(message)) {
                callback();
            }
        },

        // Fazer requisição AJAX
        ajax: function(url, options = {}) {
            const defaults = {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                }
            };
            
            const config = Object.assign(defaults, options);
            
            app.loading.show();
            return fetch(url, config)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return response.json();
                })
                .finally(() => {
                    app.loading.hide();
                });
        }
    },

    // WhatsApp
    whatsapp: {
        // Verificar status
        checkStatus: function() {
            return app.utils.ajax('/api/whatsapp/status-teste')
                .then(data => {
                    if (data.success) {
                        app.whatsapp.updateStatusUI(data.status);
                    }
                    return data;
                })
                .catch(error => {
                    console.error('Erro ao verificar status WhatsApp:', error);
                });
        },

        // Atualizar UI de status
        updateStatusUI: function(status) {
            const statusElements = document.querySelectorAll('[data-whatsapp-status]');
            
            statusElements.forEach(element => {
                const isBadge = element.classList.contains('badge');
                if (status.isConnected) {
                    if (isBadge) {
                        element.className = 'badge bg-success';
                    } else {
                        element.className = 'status-connected';
                    }
                    element.innerHTML = '<i class="bi bi-check-circle-fill"></i> Conectado';
                } else {
                    if (isBadge) {
                        element.className = 'badge bg-danger';
                    } else {
                        element.className = 'status-disconnected';
                    }
                    element.innerHTML = '<i class="bi bi-x-circle-fill"></i> Desconectado';
                }
            });
        },

        // Enviar mensagem de teste
        sendTestMessage: function() {
            return app.utils.ajax('/api/whatsapp/teste-voce-mesmo', { method: 'GET' })
                .then(data => {
                    if (data.success) {
                        app.utils.showNotification('Mensagem de teste enviada com sucesso!', 'success');
                    } else {
                        app.utils.showNotification('Falha ao enviar mensagem: ' + data.message, 'error');
                    }
                    return data;
                })
                .catch(error => {
                    app.utils.showNotification('Erro ao enviar mensagem de teste', 'error');
                });
        },

        // Reativar WhatsApp
        reactivate: function() {
            return app.utils.ajax('/api/whatsapp/reactivate-teste', { method: 'POST' })
                .then(data => {
                    if (data.success) {
                        app.utils.showNotification('WhatsApp reativado com sucesso!', 'success');
                        // Verificar status após 2 segundos
                        setTimeout(app.whatsapp.checkStatus, 2000);
                    } else {
                        app.utils.showNotification('Erro ao reativar WhatsApp: ' + data.error, 'error');
                    }
                    return data;
                })
                .catch(error => {
                    app.utils.showNotification('Erro ao reativar WhatsApp', 'error');
                });
        }
    },

    // Agenda
    agenda: {
        // Atualizar status de agendamento
        updateStatus: function(id, status) {
            return app.utils.ajax(`/agenda/${id}/status`, {
                method: 'POST',
                body: JSON.stringify({ status })
            })
            .then(data => {
                if (data.success) {
                    app.utils.showNotification('Status atualizado com sucesso!', 'success');
                    if (typeof reloadPage === 'function') {
                        reloadPage();
                    }
                } else {
                    app.utils.showNotification('Erro ao atualizar status: ' + data.message, 'error');
                }
                return data;
            });
        },

        // Cancelar agendamento
        cancel: function(id, motivo) {
            return app.utils.ajax(`/agenda/${id}/cancelar`, {
                method: 'POST',
                body: JSON.stringify({ motivo })
            })
            .then(data => {
                if (data.success) {
                    app.utils.showNotification('Agendamento cancelado com sucesso!', 'success');
                    if (typeof reloadPage === 'function') {
                        reloadPage();
                    }
                } else {
                    app.utils.showNotification('Erro ao cancelar agendamento: ' + data.message, 'error');
                }
                return data;
            });
        }
    },

    // Lembretes
    lembretes: {
        // Enviar lembrete
        send: function(id) {
            return app.utils.ajax(`/lembretes/${id}/enviar`, { method: 'POST' })
                .then(data => {
                    if (data.success) {
                        app.utils.showNotification('Lembrete enviado com sucesso!', 'success');
                        if (typeof reloadPage === 'function') {
                            reloadPage();
                        }
                    } else {
                        app.utils.showNotification('Erro ao enviar lembrete: ' + data.message, 'error');
                    }
                    return data;
                });
        },

        // Excluir lembrete
        delete: function(id) {
            return app.utils.ajax(`/lembretes/${id}/excluir`, { method: 'POST' })
                .then(data => {
                    if (data.success) {
                        app.utils.showNotification('Lembrete excluído com sucesso!', 'success');
                        if (typeof reloadPage === 'function') {
                            reloadPage();
                        }
                    } else {
                        app.utils.showNotification('Erro ao excluir lembrete: ' + data.message, 'error');
                    }
                    return data;
                });
        }
    }
};

// Inicialização quando o DOM estiver pronto
document.addEventListener('DOMContentLoaded', function() {
    console.log('Sistema de gestão iniciado');

    app.loading.hide();

    // Mostrar loading ao navegar via links internos
    document.addEventListener('click', function(e) {
        const a = e.target && e.target.closest ? e.target.closest('a') : null;
        if (!a) return;
        const href = a.getAttribute('href');
        if (!href) return;
        if (a.target && a.target !== '_self') return;
        if (a.hasAttribute('download')) return;
        if (href.startsWith('#')) return;
        if (href.startsWith('javascript:')) return;
        if (href.startsWith('mailto:') || href.startsWith('tel:')) return;
        if (a.getAttribute('data-bs-toggle') === 'collapse') return;
        if (a.getAttribute('data-bs-toggle') === 'offcanvas') return;
        if (a.getAttribute('data-bs-toggle') === 'modal') return;

        try {
            const url = new URL(href, window.location.href);
            if (url.origin !== window.location.origin) return;
        } catch (err) {
            // ignore
        }

        app.loading.show();
    }, true);

    // Mostrar loading ao enviar formulários
    document.addEventListener('submit', function(e) {
        const form = e.target;
        if (!form) return;
        app.loading.show();
    }, true);
    
    initBootstrapTooltips(document);

    let tooltipInitTimer = null;
    const observer = new MutationObserver((mutations) => {
        let shouldInit = false;
        for (const m of mutations) {
            if (m.addedNodes && m.addedNodes.length) {
                shouldInit = true;
                break;
            }
        }
        if (!shouldInit) return;
        if (tooltipInitTimer) clearTimeout(tooltipInitTimer);
        tooltipInitTimer = setTimeout(() => initBootstrapTooltips(document), 50);
    });
    try {
        observer.observe(document.body, { childList: true, subtree: true });
    } catch (e) {
        // ignore
    }
    
    // Verificar status do WhatsApp se estiver na página de WhatsApp
    if (document.querySelector('[data-whatsapp-status]')) {
        app.whatsapp.checkStatus();
        
        // Atualizar status periodicamente
        setInterval(app.whatsapp.checkStatus, app.config.refreshInterval);
    }
    
    // Aplicar máscaras nos formulários
    applyInputMasks();
    
    // Configurar validação de formulários
    setupFormValidation();
    
    // Configurar atalhos de teclado
    setupKeyboardShortcuts();
});

function initBootstrapTooltips(root) {
    if (typeof bootstrap === 'undefined' || !bootstrap.Tooltip) return;
    const scope = root && root.querySelectorAll ? root : document;

    const titleEls = [].slice.call(scope.querySelectorAll('[title]:not([data-bs-toggle])'));
    titleEls.forEach((el) => {
        const title = el.getAttribute('title');
        if (!title || !String(title).trim()) return;
        el.setAttribute('data-bs-toggle', 'tooltip');
    });

    const tooltipTriggerList = [].slice.call(scope.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.forEach((el) => {
        if (el._tooltipInitialized) return;
        try {
            bootstrap.Tooltip.getOrCreateInstance(el);
            el._tooltipInitialized = true;
        } catch (e) {
            // ignore
        }
    });
}

// Aplicar máscaras de input
function applyInputMasks() {
    // Máscara de CPF
    const cpfInputs = document.querySelectorAll('input[data-mask="cpf"]');
    cpfInputs.forEach(input => {
        input.addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, '');
            if (value.length > 11) value = value.slice(0, 11);
            
            if (value.length > 9) {
                value = value.slice(0, 3) + '.' + value.slice(3, 6) + '.' + value.slice(6, 9) + '-' + value.slice(9);
            } else if (value.length > 6) {
                value = value.slice(0, 3) + '.' + value.slice(3, 6) + '.' + value.slice(6);
            } else if (value.length > 3) {
                value = value.slice(0, 3) + '.' + value.slice(3);
            }
            
            e.target.value = value;
        });
    });
    
    // Máscara de telefone
    const phoneInputs = document.querySelectorAll('input[data-mask="phone"]');
    phoneInputs.forEach(input => {
        input.addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, '');
            if (value.length > 11) value = value.slice(0, 11);
            
            if (value.length > 7) {
                value = '(' + value.slice(0, 2) + ') ' + value.slice(2, 7) + '-' + value.slice(7);
            } else if (value.length > 2) {
                value = '(' + value.slice(0, 2) + ') ' + value.slice(2);
            }
            
            e.target.value = value;
        });
    });
    
    // Máscara de CEP
    const cepInputs = document.querySelectorAll('input[data-mask="cep"]');
    cepInputs.forEach(input => {
        input.addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, '');
            if (value.length > 8) value = value.slice(0, 8);
            
            if (value.length > 5) {
                value = value.slice(0, 5) + '-' + value.slice(5);
            }
            
            e.target.value = value;
        });
    });
}

// Configurar validação de formulários
function setupFormValidation() {
    const forms = document.querySelectorAll('.needs-validation');
    
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            
            form.classList.add('was-validated');
        }, false);
    });
}

// Configurar atalhos de teclado
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl + S para salvar formulários
        if (e.ctrlKey && e.key === 's') {
            e.preventDefault();
            const submitButton = document.querySelector('button[type="submit"]');
            if (submitButton) {
                submitButton.click();
            }
        }
        
        // Ctrl + N para novo cadastro
        if (e.ctrlKey && e.key === 'n') {
            e.preventDefault();
            const newButton = document.querySelector('a[href*="/novo"]');
            if (newButton) {
                window.location.href = newButton.href;
            }
        }
        
        // ESC para fechar modais
        if (e.key === 'Escape') {
            const openModal = document.querySelector('.modal.show');
            if (openModal) {
                const modal = bootstrap.Modal.getInstance(openModal);
                if (modal) {
                    modal.hide();
                }
            }
        }
    });
}

// Função global para recarregar página
function reloadPage() {
    location.reload();
}

// Exportar para uso global
window.app = app;

window.addEventListener('pageshow', function() {
    if (window.app && window.app.loading) {
        window.app.loading.hide();
    }
});

try {
    if (!window.__fetchWithLoadingInstalled && typeof window.fetch === 'function') {
        window.__fetchWithLoadingInstalled = true;
        const _fetch = window.fetch;
        window.fetch = function(...args) {
            if (window.app && window.app.loading) window.app.loading.show();
            return _fetch.apply(this, args)
                .finally(() => {
                    if (window.app && window.app.loading) window.app.loading.hide();
                });
        };
    }
} catch (e) {
    // ignore
}
