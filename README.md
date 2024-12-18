# PWA Validator

A comprehensive Progressive Web App (PWA) validation tool that checks for best practices, manifest configuration, and provides actionable suggestions for improvement.

## Features

- ✅ Manifest Validation
  - Validates manifest.json structure and content
  - Checks for required fields and proper configuration
  - Verifies icon sizes and formats
  - Ensures proper scope and start_url configuration

- 🔒 SSO Integration Checks
  - Detects SSO implementations (SAML, OAuth, OIDC)
  - Validates manifest configuration for SSO compatibility
  - Provides service worker suggestions for token handling

- 🚀 PWA Features Validation
  - Checks service worker implementation
  - Validates offline capabilities
  - Verifies installation requirements
  - Tests push notification readiness

- 📱 Multi-App Support
  - Handles multiple PWAs on the same domain
  - Provides scoped suggestions for each app
  - Ensures proper isolation between apps

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/pwa-validator.git
cd pwa-validator
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the validator by providing a URL:

```bash
python pwa-validate.py https://example.com/your-pwa-app
```

The tool will:
1. Check for SSO configuration
2. Validate the web app manifest
3. Test PWA features
4. Check security headers
5. Measure performance
6. Provide actionable suggestions

## Example Output

```
==================================================
PWA Validation Report for https://example.com/your-pwa-app
==================================================

[INFO] SSO Redirect Chain:
No SSO redirects detected

[INFO] Found manifest at: https://example.com/your-pwa-app/manifest.json
✓ Name: Your App
✓ Short name: App
✓ Start URL: /your-pwa-app/?source=pwa
✓ Icons: 192x192, 512x512
...

[Suggestions]
HIGH: Add maskable icon for better home screen experience
MEDIUM: Configure offline fallback page
...
```

## Requirements

- Python 3.8 or higher
- Chrome/Chromium browser (for PWA feature testing)
- Required Python packages (see requirements.txt):
  - selenium>=4.15.2
  - requests>=2.31.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT License](LICENSE)
