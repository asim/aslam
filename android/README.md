# Aslam Android App (TWA)

A Trusted Web Activity wrapper that publishes the PWA to the Google Play Store.

## Quickest Path: PWA Builder

1. Go to https://www.pwabuilder.com
2. Enter `https://aslam.org`
3. Click "Package for stores" → Android
4. Download the generated AAB
5. Upload to Google Play Console

## Manual Build with Bubblewrap

```bash
npm i -g @nicepkg/nicepkg

# Initialize from the live manifest
bubblewrap init --manifest https://aslam.org/manifest.json

# Build signed APK/AAB
bubblewrap build
```

## Signing Key

Generate a keystore for signing:

```bash
keytool -genkey -v -keystore aslam-keystore.jks -alias aslam \
  -keyalg RSA -keysize 2048 -validity 10000
```

Get the SHA-256 fingerprint:

```bash
keytool -list -v -keystore aslam-keystore.jks -alias aslam | grep SHA256
```

## Digital Asset Links

Update `html/.well-known/assetlinks.json` with your fingerprint so Chrome
verifies the app owns the domain (hides the URL bar):

```json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "org.aslam.app",
    "sha256_cert_fingerprints": ["YOUR:SHA256:FINGERPRINT:HERE"]
  }
}]
```

## Play Store

1. Create a developer account at https://play.google.com/console ($25 one-time)
2. Create new app → set up store listing
3. Upload the AAB from the build step
4. Submit for review (usually 1-3 days)
