const CACHE_NAME = 'medinnowhere-v2.1';
const urlsToCache = [
  '/',
  '/static/manifest.json',
  '/static/icon-192.jpg',
  '/static/icon-512.jpg',
  '/patient',
  '/terminal',
  '/history',
  '/referrals',
  '/reminders',
  '/profile',
  '/translate',
  '/bulk',
  '/about',
  '/login',
  '/register'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => response || fetch(event.request))
  );
});
