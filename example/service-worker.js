self.addEventListener('push', event => {
  console.log('[Service Worker] Push Received.');
  console.log(`[Service Worker] Push had this data: "${event.data ? event.data.text() : null}"`);

  event.waitUntil(self.registration.showNotification(
      'Test Webpush',
      {
        body: event.data ? event.data.text() : 'No payload',
      },
  ));
});
