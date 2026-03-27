/**
 * FirmaRED Service Worker — Web Push Notifications
 */

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(clients.claim()));

self.addEventListener('push', event => {
  let data = {};
  try { data = event.data.json(); } catch { data = { title: 'FirmaRED', body: event.data.text() }; }

  event.waitUntil(
    self.registration.showNotification(data.title || 'FirmaRED', {
      body:    data.body    || 'Tenés una planilla pendiente de firma',
      icon:    data.icon    || '/icon-192.png',
      badge:   data.badge   || '/badge-72.png',
      data:    data.data    || { url: '/inspeccion' },
      vibrate: [200, 100, 200],
      requireInteraction: true,
      actions: [
        { action: 'firmar', title: '✍️ Firmar ahora' },
        { action: 'later',  title: 'Más tarde' },
      ]
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data?.url || '/inspeccion';
  if (event.action === 'firmar' || !event.action) {
    event.waitUntil(clients.openWindow(url));
  }
});
