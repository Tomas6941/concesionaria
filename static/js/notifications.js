// Sistema de notificaciones temporales
function showNotification(message, type = 'success', duration = 10000) {
    console.log('Mostrando notificación:', message, type);
    
    // Crear contenedor si no existe
    let container = document.querySelector('.notification-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'notification-container';
        document.body.appendChild(container);
    }

    // Crear la notificación
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    // Iconos según el tipo
    const icons = {
        success: '✓',
        warning: '⚠',
        error: '✗',
        info: 'ℹ'
    };
    
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-icon">${icons[type] || 'ℹ'}</span>
            <span class="notification-message">${message}</span>
        </div>
        <button class="notification-close">&times;</button>
        <div class="notification-progress"></div>
    `;
    
    container.appendChild(notification);
    
    // Botón para cerrar
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', function() {
        notification.style.animation = 'slideOut 0.3s ease-in-out forwards';
        setTimeout(() => notification.remove(), 300);
    });
    
    // Auto-eliminar después de la duración
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOut 0.3s ease-in-out forwards';
            setTimeout(() => notification.remove(), 300);
        }
    }, duration);
}

// Función para verificar parámetros URL
function checkUrlParams() {
    console.log('Verificando parámetros URL...');
    const urlParams = new URLSearchParams(window.location.search);
    
    // Mostrar todos los parámetros para debug
    console.log('Parámetros encontrados:');
    urlParams.forEach((value, key) => {
        console.log(`- ${key}: ${value}`);
    });
    
    // NOTIFICACIÓN DE REGISTRO
    if (urlParams.has('registered')) {
        console.log('✓ Mostrando notificación de registro');
        showNotification(
            'Cuenta registrada correctamente. Revisa tu Gmail y verifica tu cuenta para poder iniciar sesión.', 
            'success', 
            10000
        );
        
        // Limpiar URL
        const url = new URL(window.location);
        url.searchParams.delete('registered');
        window.history.replaceState({}, document.title, url);
        return true;
    }
    
    // NOTIFICACIÓN DE CAMBIOS SOLICITADOS
    if (urlParams.has('changes_sent')) {
        console.log('✓ Mostrando notificación de cambios solicitados');
        showNotification(
            'Se ha enviado un enlace de verificación a tu email para confirmar los cambios. Revisa tu bandeja de entrada.', 
            'info', 
            10000
        );
        
        const url = new URL(window.location);
        url.searchParams.delete('changes_sent');
        window.history.replaceState({}, document.title, url);
        return true;
    }
    
    // NOTIFICACIÓN DE CAMBIOS CONFIRMADOS
    if (urlParams.has('changes_confirmed')) {
        console.log('✓ Mostrando notificación de cambios confirmados');
        showNotification('¡Cambios confirmados correctamente!', 'success', 10000);
        
        const url = new URL(window.location);
        url.searchParams.delete('changes_confirmed');
        window.history.replaceState({}, document.title, url);
        return true;
    }
    
    return false;
}

// Cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM cargado - notifications.js iniciado');
    
    // Verificar mensajes flash ocultos
    const flashMessages = document.querySelectorAll('.flash-message');
    console.log('Mensajes flash encontrados:', flashMessages.length);
    
    flashMessages.forEach(message => {
        const category = message.dataset.category || 'info';
        const text = message.textContent.trim();
        showNotification(text, category, 10000);
        message.remove();
    });
    
    // Verificar parámetros URL
    checkUrlParams();
});

// También verificar cuando la página ya estaba cargada
if (document.readyState === 'complete' || document.readyState === 'interactive') {
    setTimeout(() => {
        console.log('Página ya cargada - verificando parámetros...');
        checkUrlParams();
    }, 500);
}