self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { type: 'test' }; }
  const title = d.type === 'sign' ? `SSH: ${d.key || 'signature needed'}` : 'SSH keys';
  const body = d.type === 'sign' ? [d.user ? `login as ${d.user}` : '', d.summary].filter(Boolean).join('\n') || 'Open to sign the request' : 'Notifications work.';
  e.waitUntil((async () => {
    await self.registration.showNotification(title, { body, tag: d.id || 'test', data: d, requireInteraction: d.type === 'sign' });
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of clients) c.postMessage(d);
  })());
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (clients.length) { await clients[0].focus(); clients[0].postMessage(e.notification.data); }
    else await self.clients.openWindow('/');
  })());
});
