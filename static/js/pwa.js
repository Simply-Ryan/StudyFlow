// PWA Installation and Service Worker Registration
(function() {
  'use strict';

  let deferredPrompt;
  let installButton;

  // Register Service Worker
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker
        .register('/static/sw.js')
        .then((registration) => {
          console.log('✅ Service Worker registered:', registration.scope);

          // Check for updates periodically
          setInterval(() => {
            registration.update();
          }, 60000); // Check every minute

          // Handle updates
          registration.addEventListener('updatefound', () => {
            const newWorker = registration.installing;
            
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                // New service worker available
                showUpdateNotification();
              }
            });
          });
        })
        .catch((error) => {
          console.error('❌ Service Worker registration failed:', error);
        });
    });
  }

  // Show update notification
  function showUpdateNotification() {
    const notification = document.createElement('div');
    notification.className = 'pwa-update-notification';
    notification.innerHTML = `
      <div class="pwa-update-content">
        <i class="fas fa-sync-alt"></i>
        <span>New version available!</span>
        <button onclick="updateServiceWorker()" class="btn-small btn-primary">Update</button>
        <button onclick="this.parentElement.parentElement.remove()" class="btn-small btn-ghost">Later</button>
      </div>
    `;
    document.body.appendChild(notification);
    
    setTimeout(() => notification.classList.add('show'), 100);
  }

  // Update service worker
  window.updateServiceWorker = function() {
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.getRegistration().then((registration) => {
        if (registration && registration.waiting) {
          registration.waiting.postMessage({ type: 'SKIP_WAITING' });
          window.location.reload();
        }
      });
    }
  };

  // Handle install prompt
  window.addEventListener('beforeinstallprompt', (e) => {
    console.log('💡 Install prompt available');
    e.preventDefault();
    deferredPrompt = e;
    
    // Show install button
    showInstallButton();
  });

  // Show install button in UI
  function showInstallButton() {
    // Check if button already exists
    if (document.getElementById('pwaInstallBtn')) return;

    const installBtn = document.createElement('button');
    installBtn.id = 'pwaInstallBtn';
    installBtn.className = 'pwa-install-btn';
    installBtn.innerHTML = '<i class="fas fa-download"></i> Install App';
    installBtn.addEventListener('click', installApp);
    
    // Add to navbar or create floating button
    const navbar = document.querySelector('.navbar .nav-links');
    if (navbar) {
      navbar.appendChild(installBtn);
    } else {
      installBtn.classList.add('floating');
      document.body.appendChild(installBtn);
    }

    installButton = installBtn;
  }

  // Install app
  async function installApp() {
    if (!deferredPrompt) {
      console.log('No install prompt available');
      return;
    }

    deferredPrompt.prompt();
    
    const { outcome } = await deferredPrompt.userChoice;
    console.log(`Install prompt outcome: ${outcome}`);

    if (outcome === 'accepted') {
      console.log('✅ PWA installed successfully');
      if (installButton) {
        installButton.remove();
      }
    }

    deferredPrompt = null;
  }

  // Handle successful installation
  window.addEventListener('appinstalled', () => {
    console.log('✅ StudyFlow PWA installed');
    deferredPrompt = null;
    
    if (installButton) {
      installButton.remove();
    }

    // Show success message
    if (typeof showToast === 'function') {
      showToast('StudyFlow installed successfully!', 'success');
    }
  });

  // Detect if running as PWA
  function isPWA() {
    return window.matchMedia('(display-mode: standalone)').matches ||
           window.navigator.standalone === true;
  }

  if (isPWA()) {
    console.log('🚀 Running as PWA');
    document.body.classList.add('pwa-mode');
  }

  // Network status monitoring
  window.addEventListener('online', () => {
    console.log('🌐 Back online');
    if (typeof showToast === 'function') {
      showToast('Connection restored', 'success');
    }
    document.body.classList.remove('offline-mode');
  });

  window.addEventListener('offline', () => {
    console.log('📴 Offline');
    if (typeof showToast === 'function') {
      showToast('You are offline. Some features may be limited.', 'warning');
    }
    document.body.classList.add('offline-mode');
  });

  // Background sync registration (when available)
  if ('sync' in registration) {
    // Register sync when going offline
    window.addEventListener('offline', () => {
      navigator.serviceWorker.ready.then((registration) => {
        return registration.sync.register('sync-data');
      }).catch((error) => {
        console.error('Background sync registration failed:', error);
      });
    });
  }

})();
