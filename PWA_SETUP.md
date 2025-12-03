# Progressive Web App (PWA) Setup Guide

StudyFlow is now a Progressive Web App! This means you can install it on your device for a native app-like experience.

## Features

### ✨ Core PWA Features
- **Installable**: Add StudyFlow to your home screen on any device
- **Offline Support**: Access cached pages and content without internet
- **Fast Loading**: Cached assets load instantly
- **Background Sync**: Changes made offline sync when you're back online
- **Push Notifications**: Receive updates about study sessions (when enabled)
- **App-like Experience**: No browser UI, full-screen experience

### 📱 Mobile Features
- Works on iOS, Android, and desktop
- Adaptive to different screen sizes
- Touch-optimized interface
- Respects safe areas (notch, status bar)

### 🔄 Smart Caching
- **Static Assets**: CSS, JS, images cached for instant loading
- **Runtime Caching**: Pages you visit are cached automatically
- **Network First**: API calls always fetch fresh data when online
- **Graceful Degradation**: Shows cached content when offline

## Installation

### On Desktop (Chrome, Edge, Opera)

1. Visit StudyFlow in your browser
2. Look for the **Install App** button in the navigation bar
3. Click it and confirm installation
4. Or click the install icon (⊕) in the address bar

### On Android (Chrome)

1. Visit StudyFlow in Chrome
2. Tap the menu (⋮) button
3. Select **"Add to Home Screen"** or **"Install App"**
4. Confirm installation
5. Find StudyFlow icon on your home screen

### On iOS (Safari)

1. Visit StudyFlow in Safari
2. Tap the Share button (□↑)
3. Scroll down and tap **"Add to Home Screen"**
4. Edit the name if desired and tap **"Add"**
5. Find StudyFlow icon on your home screen

## Offline Capabilities

### What Works Offline
✅ View previously visited pages
✅ Read cached study sessions
✅ Access downloaded notes and flashcards
✅ Browse your profile and settings
✅ View study analytics (cached data)

### What Requires Internet
❌ Creating new sessions
❌ Real-time chat
❌ Fetching new AI recommendations
❌ Uploading files
❌ Live updates and notifications

## Service Worker

The service worker (`sw.js`) handles:
- **Caching Strategy**: Determines what gets cached and when
- **Offline Support**: Serves cached content when offline
- **Background Sync**: Queues actions to execute when online
- **Update Management**: Notifies users of new versions

### Updating the App

When a new version is available:
1. You'll see a notification at the top of the page
2. Click **"Update"** to refresh with the latest version
3. Or click **"Later"** to update on next visit

### Manual Cache Clear

To force a fresh download of all assets:
```javascript
// Open browser console and run:
navigator.serviceWorker.getRegistrations().then(registrations => {
    registrations.forEach(reg => reg.unregister());
});
caches.keys().then(names => {
    names.forEach(name => caches.delete(name));
});
// Then refresh the page
```

## Manifest Configuration

The `manifest.json` file defines:
- App name and description
- Icons for various devices
- Theme colors
- Display mode (standalone)
- Start URL
- Shortcuts to common actions

## Development

### Testing PWA Features Locally

1. **HTTPS Required**: PWAs require HTTPS (localhost is exempt)
   ```bash
   # For production, use a proper SSL certificate
   # For local testing, localhost works fine
   python app.py
   ```

2. **Audit with Lighthouse**:
   - Open Chrome DevTools (F12)
   - Go to "Lighthouse" tab
   - Select "Progressive Web App"
   - Click "Generate report"

3. **Test Offline Mode**:
   - Open DevTools → Network tab
   - Select "Offline" from the throttling dropdown
   - Refresh the page to test offline behavior

### Updating Service Worker

When you modify `sw.js`:
1. Update the `CACHE_NAME` version number
2. Users will be prompted to update
3. Old caches are automatically cleaned up

```javascript
// In sw.js
const CACHE_NAME = 'studyflow-v2'; // Increment version
```

## Browser Support

| Browser | Desktop | Mobile |
|---------|---------|--------|
| Chrome | ✅ Full | ✅ Full |
| Edge | ✅ Full | ✅ Full |
| Firefox | ✅ Full | ✅ Full |
| Safari | ⚠️ Limited | ⚠️ Limited* |
| Opera | ✅ Full | ✅ Full |

*iOS Safari has limited PWA support (no push notifications, limited background sync)

## Troubleshooting

### Install Button Not Showing
- Make sure you're using HTTPS (or localhost)
- Check browser console for errors
- Ensure `manifest.json` is valid
- Verify all required icons exist

### Service Worker Not Registering
- Check browser console for errors
- Verify `sw.js` is accessible at `/static/sw.js`
- Ensure no syntax errors in service worker
- Check browser compatibility

### Icons Not Displaying
- Verify icons exist in `/static/icons/` directory
- Check icon sizes match manifest entries
- Ensure PNG format (not SVG for some browsers)
- Clear cache and reinstall

### Offline Mode Not Working
- Check service worker is registered and active
- Verify caching strategy in `sw.js`
- Use browser DevTools → Application → Service Workers
- Check Cache Storage for cached resources

## Performance Tips

1. **Optimize Images**: Compress icons for faster loading
2. **Lazy Load**: Load resources as needed
3. **Minimize Cache**: Don't cache everything, be selective
4. **Update Strategy**: Balance freshness with offline access

## Security Considerations

- Service workers only work over HTTPS
- Be careful what you cache (don't cache sensitive data)
- Regularly update service worker for security patches
- Use appropriate cache expiration strategies

## Resources

- [PWA Documentation](https://web.dev/progressive-web-apps/)
- [Service Worker API](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API)
- [Web App Manifest](https://developer.mozilla.org/en-US/docs/Web/Manifest)
- [Workbox (Advanced Caching)](https://developers.google.com/web/tools/workbox)
