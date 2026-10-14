"""PWA metadata, manifest links, and service worker registration for Streamlit."""

from __future__ import annotations

import streamlit as st


def get_pwa_meta_tags() -> str:
    """Generate HTML snippet injecting manifest, theme color, and service worker.

    Returns:
        HTML string containing meta tags and service worker registration script.
    """
    return """
<link rel="manifest" href="static/manifest.json">
<meta name="theme-color" content="#0F141C">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<script>
if ('serviceWorker' in navigator) {
  window.addEventListener('load', function() {
    navigator.serviceWorker.register('static/service-worker.js')
      .then(function(registration) {
        console.log('[Sniffle PWA] ServiceWorker registered with scope:', registration.scope);
      })
      .catch(function(err) {
        console.warn('[Sniffle PWA] ServiceWorker registration failed:', err);
      });
  });
}
</script>
""".strip()


def inject_pwa_assets() -> None:
    """Inject PWA meta tags and service worker registration into the Streamlit app."""
    st.html(get_pwa_meta_tags())
