document.addEventListener('DOMContentLoaded', function() {
  console.log('🚀 NetAnalytics Pro v2.0 - Sistema de Performance Inicializado');

  // Efeito de fade-in no título
  const title = document.querySelector('.title-glow');
  if (title) {
    title.style.opacity = '0';
    setTimeout(() => {
      title.style.transition = 'opacity 2s ease';
      title.style.opacity = '1';
    }, 300);
  }

  // Loading state otimizado para formulários
  const captureForm = document.getElementById('captureForm');
  if (captureForm) {
    captureForm.addEventListener('submit', function(e) {
      const submitBtn = document.getElementById('captureBtn');
      if (submitBtn && !submitBtn.querySelector('.spinner-border')) {
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Capturando...';
        submitBtn.disabled = true;
        
        // Performance: Timeout inteligente baseado na quantidade de pacotes
        const packetCount = parseInt(document.getElementById('packetCount').value) || 100;
        const timeout = Math.min(60000, packetCount * 100); // Máximo 60 segundos
        
        setTimeout(() => {
          if (submitBtn.disabled) {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
            showToast('A captura está processando...', 'info');
          }
        }, timeout);
      }
    });
  }

  // Feedback de performance em tempo real
  const packetCountInput = document.getElementById('packetCount');
  const packetInfo = document.getElementById('packetInfo');
  
  if (packetCountInput && packetInfo) {
    packetCountInput.addEventListener('input', function() {
      const count = parseInt(this.value) || 0;
      let performanceText = '';
      let performanceClass = 'text-success';
      
      if (count <= 100) {
        performanceText = '⚡ Performance máxima';
        performanceClass = 'text-success';
      } else if (count <= 500) {
        performanceText = '🚀 Performance alta';
        performanceClass = 'text-info';
      } else if (count <= 2000) {
        performanceText = '📊 Performance média';
        performanceClass = 'text-warning';
      } else {
        performanceText = '🐢 Performance reduzida';
        performanceClass = 'text-danger';
      }
      
      packetInfo.textContent = performanceText;
      packetInfo.className = 'form-text ' + performanceClass;
    });
  }

  // Animações otimizadas para cards
  const animateCards = () => {
    const sessionCards = document.querySelectorAll('.session-card');
    sessionCards.forEach((card, index) => {
      card.style.opacity = '0';
      card.style.transform = 'translateY(20px)';
      setTimeout(() => {
        card.style.transition = 'all 0.5s ease';
        card.style.opacity = '1';
        card.style.transform = 'translateY(0)';
      }, 100 * index);
    });
  };

  // Executar animações quando a aba mudar
  const tabPanes = document.querySelectorAll('.tab-pane');
  tabPanes.forEach(pane => {
    pane.addEventListener('shown.bs.tab', animateCards);
  });

  // Inicializar animações
  animateCards();

  // Sistema de notificações de performance
  window.showToast = function(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container') || createToastContainer();
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${type} border-0`;
    toast.setAttribute('data-bs-delay', '3000');
    toast.innerHTML = `
      <div class="d-flex">
        <div class="toast-body">
          <i class="fas fa-${getToastIcon(type)} me-2"></i>
          ${message}
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    `;
    
    toastContainer.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    toast.addEventListener('hidden.bs.toast', () => {
      toast.remove();
    });
  };

  function createToastContainer() {
    const container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container position-fixed top-0 end-0 p-3';
    container.style.zIndex = '9999';
    document.body.appendChild(container);
    return container;
  }

  function getToastIcon(type) {
    const icons = {
      'info': 'info-circle',
      'success': 'check-circle',
      'warning': 'exclamation-triangle',
      'danger': 'exclamation-circle'
    };
    return icons[type] || 'info-circle';
  }

  // Monitoramento de performance da página
  let pageLoadTime = performance.now();
  window.addEventListener('load', () => {
    pageLoadTime = performance.now() - pageLoadTime;
    console.log(`📊 Página carregada em ${pageLoadTime.toFixed(2)}ms`);
    
    if (pageLoadTime < 1000) {
      showToast('⚡ Performance excelente', 'success');
    }
  });

  // Auto-dismiss para alertas com timing inteligente
  const alerts = document.querySelectorAll('.alert');
  alerts.forEach(alert => {
    const dismissTime = alert.classList.contains('alert-danger') ? 15000 : 10000;
    setTimeout(() => {
      if (alert.classList.contains('show')) {
        const bsAlert = new bootstrap.Alert(alert);
        bsAlert.close();
      }
    }, dismissTime);
  });

  // Tooltips de performance
  const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
  tooltips.forEach(tooltip => {
    new bootstrap.Tooltip(tooltip);
  });

  // Indicador de performance em tempo real
  const updatePerformanceIndicator = () => {
    const now = performance.now();
    const performanceIndicator = document.getElementById('performance-indicator') || createPerformanceIndicator();
    performanceIndicator.textContent = `⚡ ${now.toFixed(0)}ms`;
  };

  function createPerformanceIndicator() {
    const indicator = document.createElement('div');
    indicator.id = 'performance-indicator';
    indicator.className = 'position-fixed bottom-0 end-0 m-3 p-2 bg-dark text-success rounded';
    indicator.style.zIndex = '9999';
    indicator.style.fontSize = '0.8rem';
    document.body.appendChild(indicator);
    return indicator;
  }

  // Atualizar indicador a cada 2 segundos
  setInterval(updatePerformanceIndicator, 2000);
  updatePerformanceIndicator();

  console.log('✅ Todos os sistemas de performance inicializados');
});