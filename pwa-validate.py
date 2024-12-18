# PWA Best Practices Checker
import requests
import json
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import time
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum
import sys

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class Priority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4

@dataclass
class Suggestion:
    title: str
    description: str
    priority: Priority
    implementation: str

def print_colored(text: str, color: str, bold: bool = False, end: str = '\n') -> None:
    if bold:
        print(f"{Colors.BOLD}{color}{text}{Colors.ENDC}", end=end)
    else:
        print(f"{color}{text}{Colors.ENDC}", end=end)

def print_progress(step: str, total_steps: int, current_step: int) -> None:
    percentage = (current_step / total_steps) * 100
    print_colored(f"\r[{step}] Progress: {percentage:.1f}%", Colors.BLUE, end='\r')
    sys.stdout.flush()

def check_redirects(url: str) -> None:
    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code in [301, 302]:
            print_colored(f"[PASS] Redirect detected for {url} -> {response.headers['Location']}", Colors.GREEN)
        else:
            print_colored(f"[INFO] No redirection detected for {url}", Colors.YELLOW)
    except requests.RequestException as e:
        print_colored(f"[ERROR] Failed to check redirects for {url}: {e}", Colors.RED)

def check_meta_tags(driver: webdriver.Chrome) -> None:
    meta_tags = driver.execute_script(
        "return Array.from(document.getElementsByTagName('meta')).map(tag => ({name: tag.name, content: tag.content}));")
    required_meta = ["viewport", "description"]
    for tag in required_meta:
        if any(meta['name'] == tag for meta in meta_tags):
            print_colored(f"[PASS] Meta tag '{tag}' detected", Colors.GREEN)
        else:
            print_colored(f"[ERROR] Meta tag '{tag}' not found", Colors.RED)

def check_robots_txt(url: str) -> None:
    robots_url = f"{url.rstrip('/')}/robots.txt"
    try:
        response = requests.get(robots_url)
        if response.status_code == 200:
            print_colored(f"[PASS] robots.txt found at {robots_url}", Colors.GREEN)
        else:
            print_colored(f"[ERROR] robots.txt not found at {robots_url}", Colors.RED)
    except requests.RequestException as e:
        print_colored(f"[ERROR] Failed to access {robots_url}: {e}", Colors.RED)

def check_security_headers(url: str) -> tuple[int, list[Suggestion]]:
    target_domain = urlparse(url).netloc
    app_path = urlparse(url).path.rstrip('/')
    current_domain = urlparse(url).netloc
    
    # Skip security checks if we're not on the target domain
    if current_domain != target_domain:
        return 0, []
        
    security_suggestions = []
    security_score = 0
    try:
        response = requests.head(url)
        headers = {
            'Content-Security-Policy': {
                'weight': 20,
                'name': 'CSP',
                'description': 'Prevents XSS attacks by controlling resource loading',
                'example': f"""Add to your web server configuration:

                    Apache:
                    ```apache
                    <Location "{app_path}">
                        Header set Content-Security-Policy "default-src 'self';
                        script-src 'self' 'unsafe-inline' 'unsafe-eval';
                        style-src 'self' 'unsafe-inline';
                        img-src 'self' data: https:;
                        font-src 'self';
                        connect-src 'self';"
                    </Location>
                    ```
                    
                    Nginx:
                    ```nginx
                    location {app_path} {{
                        add_header Content-Security-Policy "default-src 'self';
                        script-src 'self' 'unsafe-inline' 'unsafe-eval';
                        style-src 'self' 'unsafe-inline';
                        img-src 'self' data:";
                    }}
                    ```"""
            },
            'X-Content-Type-Options': {
                'weight': 10,
                'name': 'No Sniffing',
                'description': 'Prevents MIME type sniffing',
                'example': f"""Add to your web server configuration:
                    
                    Apache:
                    ```apache
                    <Location "{app_path}">
                        Header set X-Content-Type-Options "nosniff"
                    </Location>
                    ```
                    
                    Nginx:
                    ```nginx
                    location {app_path} {{
                        add_header X-Content-Type-Options "nosniff";
                    }}
                    ```"""
            },
            'X-Frame-Options': {
                'weight': 10,
                'name': 'Frame Options',
                'description': 'Prevents clickjacking attacks',
                'example': f"""Add to your web server configuration:
                    
                    Apache:
                    ```apache
                    <Location "{app_path}">
                        Header set X-Frame-Options "SAMEORIGIN"
                    </Location>
                    ```
                    
                    Nginx:
                    ```nginx
                    location {app_path} {{
                        add_header X-Frame-Options "SAMEORIGIN";
                    }}
                    ```"""
            },
            'X-XSS-Protection': {
                'weight': 10,
                'name': 'XSS Protection',
                'description': 'Enables browser XSS filtering',
                'example': f"""Add to your web server configuration:
                    
                    Apache:
                    ```apache
                    <Location "{app_path}">
                        Header set X-XSS-Protection "1; mode=block"
                    </Location>
                    ```
                    
                    Nginx:
                    ```nginx
                    location {app_path} {{
                        add_header X-XSS-Protection "1; mode=block";
                    }}
                    ```"""
            }
        }
        
        for header, details in headers.items():
            if header in response.headers:
                print_colored(f"[PASS] {details['name']} header found: {response.headers[header]}", Colors.GREEN)
                security_score += details['weight']
            else:
                print_colored(f"[WARN] {details['name']} header not found", Colors.YELLOW)
                security_suggestions.append(Suggestion(
                    title=f"Missing {details['name']} Header",
                    description=details['description'],
                    priority=Priority.HIGH,
                    implementation=details['example']
                ))
        
        return security_score, security_suggestions
    except requests.RequestException as e:
        print_colored(f"[ERROR] Failed to check security headers: {e}", Colors.RED)
        return 0, []

def check_web_capabilities(driver: webdriver.Chrome) -> None:
    capabilities = {
        'Geolocation': 'navigator.geolocation',
        'Camera': 'navigator.mediaDevices?.getUserMedia',
        'Bluetooth': 'navigator.bluetooth',
        'USB': 'navigator.usb',
        'Web Share': 'navigator.share',
        'Notifications': 'Notification',
        'Push API': 'navigator.serviceWorker?.pushManager',
        'Background Sync': 'navigator.serviceWorker?.sync'
    }
    
    for cap, api in capabilities.items():
        is_supported = driver.execute_script(f"return typeof {api} !== 'undefined'")
        print_colored(f"[INFO] {cap} API: {'Supported' if is_supported else 'Not supported'}", Colors.YELLOW)

def validate_icons(icons: List[Dict[str, Any]]) -> List[str]:
    if not icons:
        return ["No icons found in manifest"]
    
    required_sizes = {
        "192x192": False,
        "512x512": False,
        "maskable": False
    }
    
    issues = []
    for icon in icons:
        if 'sizes' in icon:
            if '192x192' in icon['sizes']:
                required_sizes['192x192'] = True
            if '512x512' in icon['sizes']:
                required_sizes['512x512'] = True
        if 'purpose' in icon and 'maskable' in icon['purpose']:
            required_sizes['maskable'] = True
    
    if not required_sizes['192x192']:
        issues.append("[WARN] Missing 192x192 icon")
    if not required_sizes['512x512']:
        issues.append("[WARN] Missing 512x512 icon")
    if not required_sizes['maskable']:
        issues.append("[WARN] Missing maskable icon")
    
    return issues

def check_manifest_score(manifest: Dict[str, Any], url: str) -> tuple[int, list[Suggestion]]:
    """Check the manifest score and return improvement suggestions."""
    score = 0
    suggestions = []
    target_domain = urlparse(url).netloc
    app_path = urlparse(url).path.rstrip('/')
    
    if not manifest:
        suggestions.append(Suggestion(
            title="Add Web App Manifest",
            description="A web app manifest is required for PWA installation",
            priority=Priority.CRITICAL,
            implementation=f"""
                1. Create manifest.json at https://{target_domain}{app_path}/manifest.json:
                ```json
                {{
                  "name": "Your App Name",
                  "short_name": "App",
                  "start_url": "{app_path}/?source=pwa",
                  "scope": "{app_path}/",
                  "display": "standalone",
                  "background_color": "#ffffff",
                  "theme_color": "#YOUR_COLOR",
                  "icons": [
                    {{
                      "src": "{app_path}/icon-192x192.png",
                      "sizes": "192x192",
                      "type": "image/png",
                      "purpose": "any maskable"
                    }},
                    {{
                      "src": "{app_path}/icon-512x512.png",
                      "sizes": "512x512",
                      "type": "image/png",
                      "purpose": "any"
                    }}
                  ]
                }}
                ```

                2. Add these meta tags to your HTML <head> section:
                ```html
                <!-- Web App Manifest -->
                <link rel="manifest" href="{app_path}/manifest.json">
                
                <!-- iOS/Safari specific tags -->
                <meta name="apple-mobile-web-app-capable" content="yes">
                <meta name="apple-mobile-web-app-status-bar-style" content="black">
                <meta name="apple-mobile-web-app-title" content="Your App Name">
                <link rel="apple-touch-icon" href="{app_path}/icon-192x192.png">
                
                <!-- Theme and UI -->
                <meta name="theme-color" content="#YOUR_COLOR">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                ```

                3. Configure your web server to serve manifest.json with correct MIME type:
                   Apache:
                   ```apache
                   <Location "{app_path}/manifest.json">
                       AddType application/manifest+json .json
                   </Location>
                   ```
                   
                   Nginx:
                   ```nginx
                   location {app_path}/manifest.json {{
                       types {{
                           application/manifest+json json;
                       }}
                   }}
                   ```

                4. Create and store your app icons at:
                   - https://{target_domain}{app_path}/icon-192x192.png
                   - https://{target_domain}{app_path}/icon-512x512.png
                """
        ))
        return score, suggestions

    # Critical checks
    if not manifest.get('name'):
        suggestions.append(Suggestion(
            title="Missing Name",
            description="Name is required for PWA installation",
            priority=Priority.CRITICAL,
            implementation=f"Add 'name': 'Your App Name' to your manifest.json at https://{target_domain}{app_path}/manifest.json"
        ))
    else:
        score += 20

    if not manifest.get('start_url'):
        suggestions.append(Suggestion(
            title="Missing Start URL",
            description="Start URL is required for PWA installation",
            priority=Priority.CRITICAL,
            implementation=f"Add 'start_url': '{app_path}/?source=pwa' to your manifest.json at https://{target_domain}{app_path}/manifest.json"
        ))
    else:
        score += 20

    icons = manifest.get('icons', [])
    if not icons:
        suggestions.append(Suggestion(
            title="Missing Icons",
            description="Icons are required for PWA installation",
            priority=Priority.CRITICAL,
            implementation=f"""Add icons to your manifest.json at https://{target_domain}{app_path}/manifest.json:
            "icons": [
                {{
                    "src": "{app_path}/icon-192x192.png",
                    "sizes": "192x192",
                    "type": "image/png",
                    "purpose": "any maskable"
                }},
                {{
                    "src": "{app_path}/icon-512x512.png",
                    "sizes": "512x512",
                    "type": "image/png",
                    "purpose": "any"
                }}
            ]"""
        ))
    else:
        icon_score, icon_suggestions = validate_icons(icons)
        score += icon_score
        suggestions.extend(icon_suggestions)

    # High priority checks
    if not manifest.get('short_name'):
        suggestions.append(Suggestion(
            title="Missing Short Name",
            description="Short name is used on the user's home screen",
            priority=Priority.HIGH,
            implementation=f"Add 'short_name': 'App' to your manifest.json at https://{target_domain}{app_path}/manifest.json"
        ))
    else:
        score += 10

    if not manifest.get('display'):
        suggestions.append(Suggestion(
            title="Missing Display Mode",
            description="Display mode defines how the app appears on launch",
            priority=Priority.HIGH,
            implementation=f"Add 'display': 'standalone' to your manifest.json at https://{target_domain}{app_path}/manifest.json"
        ))
    else:
        score += 10

    if not manifest.get('background_color'):
        suggestions.append(Suggestion(
            title="Missing Background Color",
            description="Background color is shown during app load",
            priority=Priority.HIGH,
            implementation=f"Add 'background_color': '#FFFFFF' to your manifest.json at https://{target_domain}{app_path}/manifest.json"
        ))
    else:
        score += 10

    if not manifest.get('theme_color'):
        suggestions.append(Suggestion(
            title="Missing Theme Color",
            description="Theme color defines the app's color scheme",
            priority=Priority.HIGH,
            implementation=f"Add 'theme_color': '#000000' to your manifest.json at https://{target_domain}{app_path}/manifest.json"
        ))
    else:
        score += 10

    return score, suggestions

def check_pwa_features(driver: webdriver.Chrome, url: str) -> tuple[int, int, list[str], list[Suggestion]]:
    """Check PWA features and return improvement suggestions."""
    score = 0
    max_score = 100
    results = []
    suggestions = []
    app_path = urlparse(url).path.rstrip('/')
    
    try:
        # Check for service worker registration
        has_sw = driver.execute_script('return navigator.serviceWorker ? true : false;')
        if has_sw:
            score += 20
            results.append("[PASS] Service Worker API available")
        else:
            results.append("[FAIL] Service Worker API not available")
            suggestions.append(Suggestion(
                title="Add Service Worker Support",
                description="Service Worker is required for offline functionality",
                priority=Priority.HIGH,
                implementation=f"""
                    1. Create a service worker file at https://{urlparse(url).netloc}{app_path}/service-worker.js:
                    ```javascript
                    // https://{urlparse(url).netloc}{app_path}/service-worker.js
                    const CACHE_NAME = '{app_path}-v1';
                    const urlsToCache = [
                        '{app_path}/',
                        '{app_path}/index.html',
                        '{app_path}/styles.css',
                        '{app_path}/app.js',
                        '{app_path}/manifest.json',
                        '{app_path}/icon-192x192.png',
                        '{app_path}/icon-512x512.png'
                    ];

                    self.addEventListener('install', (event) => {{
                        event.waitUntil(
                            caches.open(CACHE_NAME).then((cache) => {{
                                return cache.addAll(urlsToCache);
                            }})
                        );
                    }});

                    self.addEventListener('fetch', (event) => {{
                        event.respondWith(
                            caches.match(event.request).then((response) => {{
                                return response || fetch(event.request);
                            }})
                        );
                    }});
                    ```

                    2. Register the service worker in your main JavaScript:
                    ```javascript
                    // https://{urlparse(url).netloc}{app_path}/app.js
                    if ('serviceWorker' in navigator) {{
                        navigator.serviceWorker.register('{app_path}/service-worker.js', {{
                            scope: '{app_path}/'
                        }}).then(registration => {{
                            console.log('Service Worker registered with scope:', registration.scope);
                        }}).catch(error => {{
                            console.error('Service Worker registration failed:', error);
                        }});
                    }}
                    ```

                    3. Configure your web server to serve service-worker.js with correct headers:
                       Apache:
                       ```apache
                       <Location "{app_path}/service-worker.js">
                           Header set Service-Worker-Allowed "{app_path}/"
                       </Location>
                       ```
                       Nginx:
                       ```nginx
                       location {app_path}/service-worker.js {{
                           add_header Service-Worker-Allowed "{app_path}/";
                       }}
                       ```
                    """
            ))

        # Check for HTTPS
        is_https = driver.execute_script('return window.location.protocol === "https:" ? true : false;')
        if is_https:
            score += 20
            results.append("[PASS] HTTPS detected")
        else:
            results.append("[FAIL] HTTPS not detected")
            suggestions.append(Suggestion(
                title="Enable HTTPS",
                description="HTTPS is required for secure communication",
                priority=Priority.CRITICAL,
                implementation=f"""
                    1. Obtain an SSL certificate (e.g., from Let's Encrypt)
                    2. Install the certificate on your server
                    3. Configure your server to redirect HTTP to HTTPS
                    
                    For Apache:
                    ```apache
                    <VirtualHost *:80>
                        ServerName yourdomain.com
                        Redirect permanent / https://yourdomain.com/
                    </VirtualHost>
                    ```
                    
                    For Nginx:
                    ```nginx
                    server {{
                        listen 80;
                        server_name yourdomain.com;
                        return 301 https://$server_name$request_uri;
                    }}
                    ```
                    """
            ))

        # Check for responsive design
        has_viewport = driver.execute_script('return document.querySelector("meta[name=\'viewport\']") ? true : false;')
        if has_viewport:
            score += 20
            results.append("[PASS] Viewport meta tag detected")
        else:
            results.append("[FAIL] Viewport meta tag not detected")
            suggestions.append(Suggestion(
                title="Add Responsive Design",
                description="Responsive design is required for a good user experience",
                priority=Priority.HIGH,
                implementation=f"""
                    1. Add viewport meta tag:
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                    
                    2. Add responsive CSS:
                    ```css
                    @media (max-width: 768px) {{
                        /* Mobile styles */
                    }}
                    
                    @media (min-width: 769px) and (max-width: 1024px) {{
                        /* Tablet styles */
                    }}
                    
                    @media (min-width: 1025px) {{
                        /* Desktop styles */
                    }}
                    ```
                    """
            ))

        # Check for installability
        is_installable = driver.execute_script('return window.matchMedia("(display-mode: standalone)").matches || ("standalone" in window.navigator && window.navigator.standalone) ? true : false;')
        if is_installable:
            score += 20
            results.append("[PASS] App is installable")
        else:
            results.append("[FAIL] App is not installable")
            suggestions.append(Suggestion(
                title="Make App Installable",
                description="Installability is required for a good user experience",
                priority=Priority.CRITICAL,
                implementation=f"""
                    Ensure your manifest.json has these required fields:
                    {{
                      "name": "Your App Name",
                      "short_name": "App",
                      "start_url": "{app_path}/",
                      "display": "standalone",
                      "icons": [
                        {{
                          "src": "{app_path}/icon-192x192.png",
                          "sizes": "192x192",
                          "type": "image/png"
                        }},
                        {{
                          "src": "{app_path}/icon-512x512.png",
                          "sizes": "512x512",
                          "type": "image/png"
                        }}
                      ]
                    }}
                    """
            ))

    except Exception as e:
        print_colored(f"Error checking PWA features: {str(e)}", Colors.RED)
        
    return score, max_score, results, suggestions

def check_performance(driver: webdriver.Chrome) -> List[str]:
    metrics = {
        "First Contentful Paint": """
            return new Promise((resolve) => {
                const observer = new PerformanceObserver((list) => {
                    const entries = list.getEntries();
                    if (entries.length > 0) {
                        resolve(entries[0].startTime);
                    }
                });
                observer.observe({ entryTypes: ['paint'] });
            });
        """,
        "DOM Load Time": """
            return window.performance.timing.domContentLoadedEventEnd - 
                   window.performance.timing.navigationStart;
        """
    }
    
    results = []
    for name, script in metrics.items():
        try:
            value = driver.execute_script(script)
            results.append(f"{name}: {value}ms")
        except Exception:
            pass
    
    return results

def generate_manifest_suggestion(driver: webdriver.Chrome, url: str) -> str:
    """Generate a suggested manifest.json based on website metadata"""
    try:
        # Extract metadata from the page
        metadata = driver.execute_script("""
            return {
                title: document.title,
                description: document.querySelector('meta[name="description"]')?.content,
                themeColor: document.querySelector('meta[name="theme-color"]')?.content,
                icon: document.querySelector('link[rel="icon"]')?.href || 
                      document.querySelector('link[rel="shortcut icon"]')?.href,
                appleTouchIcon: document.querySelector('link[rel="apple-touch-icon"]')?.href
            }
        """)
        
        # Parse the URL for default scope
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Generate a basic name from the title or URL
        site_name = metadata.get('title') or parsed_url.netloc.split('.')[0].capitalize()
        short_name = site_name[:12] if len(site_name) > 12 else site_name
        
        # Get theme color or use a default
        theme_color = metadata.get('themeColor') or "#000000"
        
        # Create manifest template
        manifest = {
            "name": site_name,
            "short_name": short_name,
            "description": metadata.get('description') or f"Progressive Web App for {site_name}",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#FFFFFF",
            "theme_color": theme_color,
            "scope": parsed_url.path if parsed_url.path != "" else "/",
            "icons": [
                {
                    "src": "/icons/icon-192x192.png",
                    "sizes": "192x192",
                    "type": "image/png"
                },
                {
                    "src": "/icons/icon-512x512.png",
                    "sizes": "512x512",
                    "type": "image/png"
                },
                {
                    "src": "/icons/icon-192x192-maskable.png",
                    "sizes": "192x192",
                    "type": "image/png",
                    "purpose": "maskable"
                }
            ]
        }
        
        # Add screenshots placeholder
        manifest["screenshots"] = [
            {
                "src": "/screenshots/desktop.png",
                "sizes": "1280x720",
                "type": "image/png",
                "form_factor": "wide"
            },
            {
                "src": "/screenshots/mobile.png",
                "sizes": "750x1334",
                "type": "image/png",
                "form_factor": "narrow"
            }
        ]
        
        # Format the manifest JSON with proper indentation
        formatted_manifest = json.dumps(manifest, indent=2)
        
        # Create implementation guide
        implementation_guide = f"""
Suggested manifest.json Implementation:
------------------------------------
1. Create a manifest.json file in your root directory with the following content:

{formatted_manifest}

2. Add the following link tag to your HTML <head> section:
   <link rel="manifest" href="/manifest.json">

3. Create the following icon files:
   - /icons/icon-192x192.png (192x192 pixels)
   - /icons/icon-512x512.png (512x512 pixels)
   - /icons/icon-192x192-maskable.png (192x192 pixels with maskable support)
   
   You can use tools like https://maskable.app/editor to create maskable icons
   
4. Create screenshot files:
   - /screenshots/desktop.png (1280x720 pixels)
   - /screenshots/mobile.png (750x1334 pixels)
   
5. Ensure your server sends the correct MIME type for the manifest:
   Content-Type: application/manifest+json

Additional Recommendations:
-------------------------
1. Customize the colors to match your brand
2. Update the screenshots with actual app images
3. Add additional icon sizes if needed
4. Consider adding optional fields like:
   - categories
   - shortcuts
   - share_target
   - related_applications
"""
        return implementation_guide
        
    except Exception as e:
        return f"Error generating manifest suggestion: {str(e)}"

def validate_manifest(manifest_url: str, driver: webdriver.Chrome, url: str) -> Dict[str, Any]:
    """Validate the web app manifest and return its contents."""
    app_path = urlparse(url).path.rstrip('/')
    target_domain = urlparse(url).netloc
    current_domain = urlparse(manifest_url).netloc if manifest_url else None

    if not manifest_url:
        print_colored("[ERROR] No manifest link found in HTML", Colors.RED)
        print_colored(f"""
Suggestion: Add the manifest link in your HTML files within {app_path}/:

1. Store the manifest at: https://{target_domain}{app_path}/manifest.json
   This ensures the manifest is scoped to your app URL.

2. Add these meta tags to your HTML <head> section:
   ```html
   <!-- Web App Manifest -->
   <link rel="manifest" href="{app_path}/manifest.json">
   
   <!-- iOS/Safari specific tags -->
   <meta name="apple-mobile-web-app-capable" content="yes">
   <meta name="apple-mobile-web-app-status-bar-style" content="black">
   <meta name="apple-mobile-web-app-title" content="Your App Name">
   <link rel="apple-touch-icon" href="{app_path}/icon-192x192.png">
   
   <!-- Theme and UI -->
   <meta name="theme-color" content="#YOUR_COLOR">
   <meta name="viewport" content="width=device-width, initial-scale=1">
   ```

3. Configure your web server to serve manifest.json with the correct MIME type:
   Apache:
   ```apache
   <Location "{app_path}/manifest.json">
       AddType application/manifest+json .json
   </Location>
   ```
   
   Nginx:
   ```nginx
   location {app_path}/manifest.json {{
       types {{
           application/manifest+json json;
       }}
   }}
   ```
""", Colors.YELLOW)
        return None

    try:
        response = requests.get(manifest_url)
        if response.status_code == 404:
            print_colored(f"\n[INFO] Checking manifest at: https://{target_domain}{app_path}/manifest.json", Colors.BLUE)
            alt_manifest_url = f"https://{target_domain}{app_path}/manifest.json"
            alt_response = requests.get(alt_manifest_url)
            if alt_response.status_code == 404:
                print_colored(f"[ERROR] No manifest found at {alt_manifest_url} (Status: 404)", Colors.RED)
                return None
            response = alt_response
            manifest_url = alt_manifest_url

        if response.status_code != 200:
            print_colored(f"[ERROR] Failed to fetch manifest: {response.status_code}", Colors.RED)
            return None

        try:
            manifest = response.json()
        except json.JSONDecodeError:
            print_colored("[ERROR] Invalid JSON in manifest", Colors.RED)
            return None

        # Validate manifest content
        manifest_issues = validate_manifest_content(manifest, manifest_url, url, target_domain)
        if manifest_issues:
            for issue in manifest_issues:
                print_colored(f"[WARN] {issue}", Colors.YELLOW)

        return manifest

    except Exception as e:
        print_colored(f"[ERROR] Failed to validate manifest: {str(e)}", Colors.RED)
        return None

def validate_manifest_content(manifest: Dict[str, Any], manifest_url: str, current_url: str, target_domain: str) -> Dict[str, Any]:
    """Validate manifest content and provide specific feedback."""
    if not isinstance(manifest, dict):
        print_colored("[ERROR] Manifest must be a JSON object", Colors.RED)
        return None
        
    # Validate start_url
    if 'start_url' in manifest:
        manifest_domain = urlparse(manifest_url).netloc
        
        # Only validate start_url if we're on the target PWA domain
        if manifest_domain == target_domain:
            current_path = urlparse(current_url).path
            start_url = manifest['start_url']
            
            # Check if SSO is used before showing SSO-related warnings
            try:
                response = requests.get(current_url, allow_redirects=False)
                has_sso = False
                max_redirects = 10
                redirect_count = 0
                
                while response.status_code in [301, 302, 303, 307, 308] and redirect_count < max_redirects:
                    location = response.headers.get('Location', '')
                    if "saml" in location.lower() or "oauth" in location.lower() or "oidc" in location.lower():
                        has_sso = True
                        break
                    try:
                        response = requests.get(location, allow_redirects=False)
                        redirect_count += 1
                    except requests.exceptions.RequestException:
                        break
                
                if has_sso and (start_url == '/' or not start_url.startswith(current_path)):
                    print_colored(f"[WARN] start_url '{start_url}' may cause redirect issues after SSO login", Colors.YELLOW)
                    print_colored(f"       Consider using '{current_path}' as the start_url", Colors.YELLOW)
                    manifest['start_url'] = current_path
            except requests.exceptions.RequestException:
                # If we can't check SSO, skip the warning
                pass
    
    # Validate required fields
    required_fields = ['name', 'short_name', 'start_url', 'display', 'icons']
    for field in required_fields:
        if field not in manifest:
            print_colored(f"[ERROR] Required field '{field}' missing from manifest", Colors.RED)
            return None
            
    # Validate icons
    if not validate_icons(manifest.get('icons', [])):
        print_colored("[ERROR] Invalid or missing icons in manifest", Colors.RED)
        return None
    
    return manifest

def check_sso_redirect(url: str) -> list[Suggestion]:
    """Check if the site uses SSO and provide relevant suggestions."""
    target_domain = urlparse(url).netloc
    app_path = urlparse(url).path.rstrip('/')  # Get the app path from the URL
    print_colored("[INFO] SSO Redirect Chain:", Colors.BLUE)
    suggestions = []
    try:
        response = requests.get(url, allow_redirects=False)
        redirect_chain = []
        max_redirects = 10
        redirect_count = 0
        
        while response.status_code in [301, 302, 303, 307, 308] and redirect_count < max_redirects:
            location = response.headers.get('Location', '')
            redirect_type = "SSO" if "saml" in location.lower() or "oauth" in location.lower() or "oidc" in location.lower() else "HTTP"
            redirect_chain.append(f"{response.status_code} → {redirect_type}: {location}")
            print_colored(f"{redirect_count + 1}. {response.status_code} → {redirect_type}: {location}", Colors.BLUE)
            
            try:
                response = requests.get(location, allow_redirects=False)
                redirect_count += 1
            except requests.exceptions.RequestException:
                break
                
        if redirect_chain:
            print_colored(f"\n[INFO] Site uses SSO authentication", Colors.BLUE)
            
            # Add SSO-specific suggestions for the PWA
            suggestions.extend([
                Suggestion(
                    title="Configure PWA for SSO Support",
                    description=f"Update {target_domain}'s PWA configuration to handle SSO authentication",
                    priority=Priority.HIGH,
                    implementation=f"""
                1. Update manifest.json on {target_domain}:
                   ```json
                   {{
                     "start_url": "{app_path}/?source=pwa",
                     "scope": "{app_path}/",
                     "name": "Your App Name",
                     "short_name": "App",
                     "display": "standalone",
                     "icons": [
                       {{
                         "src": "{app_path}/icon-192x192.png",
                         "sizes": "192x192",
                         "type": "image/png"
                       }},
                       {{
                         "src": "{app_path}/icon-512x512.png",
                         "sizes": "512x512",
                         "type": "image/png"
                       }}
                     ]
                   }}
                   ```
                   
                2. Add a Service Worker to handle SSO tokens:
                   ```javascript
                   // On {target_domain}{app_path}/service-worker.js
                   // Scope the service worker to the app path
                   self.addEventListener('install', event => {{
                     self.skipWaiting();
                   }});

                   self.addEventListener('activate', event => {{
                     event.waitUntil(
                       Promise.all([
                         self.clients.claim(),
                         // Clear any old caches from different scopes
                         caches.keys().then(keys => Promise.all(
                           keys.map(key => {{
                             if (key.startsWith('auth-') && !key.includes('{app_path}')) {{
                               return caches.delete(key);
                             }}
                           }})
                         ))
                       ])
                     );
                   }});

                   self.addEventListener('fetch', event => {{
                     // Only handle requests within our app scope
                     if (event.request.url.includes('{app_path}/api/')) {{
                       event.respondWith(
                         caches.match(event.request).then(response => {{
                           if (response) {{
                             // Check if cached token is still valid
                             const token = response.headers.get('Authorization');
                             if (isTokenValid(token)) {{
                               return response;
                             }}
                           }}
                           return fetch(event.request);
                         }})
                       );
                     }}
                   }});
                   ```
                   
                3. Handle post-authentication redirects:
                   ```javascript
                   // On {target_domain}{app_path}/app.js
                   if ('serviceWorker' in navigator) {{
                     // Register service worker with specific scope
                     navigator.serviceWorker.register('{app_path}/service-worker.js', {{
                       scope: '{app_path}/'  // Explicitly set scope to app path
                     }}).then(registration => {{
                       console.log('Service Worker registered with scope:', registration.scope);
                     }}).catch(error => {{
                       console.error('Service Worker registration failed:', error);
                     }});
                   }}
                   
                   // Store SSO token after authentication
                   async function handleAuthSuccess(token) {{
                     // Use app-specific cache name
                     const cache = await caches.open('auth-{app_path.replace("/", "-")}');
                     // Store token with app-scoped URL
                     await cache.put('{app_path}/api/auth', new Response(token));
                   }}
                   ```
                """
                )
            ])
        else:
            print_colored("\n[INFO] No SSO redirects detected", Colors.BLUE)
            
    except requests.exceptions.RequestException as e:
        print_colored(f"[ERROR] Failed to check SSO redirects: {str(e)}", Colors.RED)
        
    return suggestions

def check_pwa(url: str) -> None:
    total_steps = 7
    current_step = 0
    manifest_score = 0
    all_suggestions: list[Suggestion] = []

    print_colored("\n" + "="*50, Colors.HEADER)
    print_colored(f"PWA Validation Report for {url}", Colors.HEADER, bold=True)
    print_colored("="*50 + "\n", Colors.HEADER)

    # First check for SSO
    print_progress("Checking SSO configuration", total_steps, current_step)
    sso_suggestions = check_sso_redirect(url)
    all_suggestions.extend(sso_suggestions)
    
    current_step += 1

    # Setup Chrome options
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    driver = webdriver.Chrome(options=chrome_options)
    
    try:
        print_progress("Checking manifest", total_steps, current_step)
        
        # Try to access the URL with Selenium first
        try:
            driver.get(url)
            # Wait for any client-side redirects and dynamic content
            time.sleep(3)  # Increased wait time for dynamic content
            
            # Try multiple ways to find the manifest
            manifest_url = driver.execute_script("""
                // Try standard link tag
                let manifest = document.querySelector('link[rel="manifest"]')?.href;
                if (!manifest) {
                    // Try React Helmet and other dynamic implementations
                    const reactHelmetTags = document.querySelectorAll('link[rel="manifest"]');
                    for (const tag of reactHelmetTags) {
                        if (tag.getAttribute('data-react-helmet') === 'true' || tag.href.includes('manifest')) {
                            manifest = tag.href;
                            break;
                        }
                    }
                }
                if (!manifest) {
                    // Try finding any link with manifest in the href as a fallback
                    manifest = document.querySelector('link[href*="manifest"]')?.href;
                }
                return manifest;
            """)
            
            if manifest_url:
                print_colored(f"\n[INFO] Found manifest at: {manifest_url}", Colors.BLUE)
                manifest = validate_manifest(manifest_url, driver, url)
                if manifest:
                    manifest_score, manifest_suggestions = check_manifest_score(manifest, url)
                    all_suggestions.extend(manifest_suggestions)
            else:
                print_colored("[ERROR] No manifest link found", Colors.RED)
                manifest_score = 0
                _, manifest_suggestions = check_manifest_score({}, url)
                all_suggestions.extend(manifest_suggestions)
        except Exception as e:
            print_colored(f"[ERROR] Failed to access URL: {str(e)}", Colors.RED)
            manifest_score = 0
            _, manifest_suggestions = check_manifest_score({}, url)
            all_suggestions.extend(manifest_suggestions)
        
        current_step += 1
        
        # Continue with other checks...
        print_progress("Checking PWA features", total_steps, current_step)
        features_score, features_max, feature_results, feature_suggestions = check_pwa_features(driver, url)
        for result in feature_results:
            print_colored(result, Colors.GREEN if "[PASS]" in result else Colors.RED)
        all_suggestions.extend(feature_suggestions)
        
        current_step += 1
        print_progress("Checking security", total_steps, current_step)
        security_score, security_suggestions = check_security_headers(url)
        all_suggestions.extend(security_suggestions)
        
        current_step += 1
        print_progress("Checking performance", total_steps, current_step)
        performance_metrics = check_performance(driver)
        
        current_step += 1
        print_progress("Checking SEO & Accessibility", total_steps, current_step)
        check_meta_tags(driver)
        
        # Print all suggestions grouped by priority
        if all_suggestions:
            print_colored("\nImprovement Suggestions:", Colors.YELLOW, bold=True)
            print_colored("-" * 50, Colors.BLUE)
            
            for priority in Priority:
                priority_suggestions = [s for s in all_suggestions if s.priority == priority]
                if priority_suggestions:
                    print_colored(f"\n{priority.name} Priority:", Colors.BLUE, bold=True)
                    for i, suggestion in enumerate(priority_suggestions, 1):
                        print_colored(f"\n{i}. {suggestion.title}", Colors.YELLOW)
                        print(f"   {suggestion.description}")
                        print_colored("\n   Implementation:", Colors.GREEN)
                        print(f"   {suggestion.implementation}")
                        print()
        
        print_colored("\n" + "="*50, Colors.HEADER)
        print_colored("Final PWA Score: {}/300".format(
            features_score + security_score + manifest_score
        ), Colors.HEADER, bold=True)
        print_colored("="*50 + "\n", Colors.HEADER)
        
    finally:
        driver.quit()

if __name__ == "__main__":
    import sys
    target_url = sys.argv[1] if len(sys.argv) > 1 else 'https://example.com'
    check_pwa(target_url)
