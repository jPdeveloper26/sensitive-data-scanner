=== Sensitive Data Scanner ===
Contributors: Juan Mojica
Tags:  data-protection, privacy, sensitive-data, gdpr, compliance
Requires at least: 5.0
Tested up to: 6.8
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Automatically scans your WordPress website for accidentally exposed sensitive data to help protect your privacy and security.

== Description ==

**Sensitive Data Scanner** is a comprehensive security tool that helps website administrators identify and locate accidentally exposed sensitive information across their WordPress site. In today's digital landscape, protecting sensitive data is crucial for maintaining user trust and complying with privacy regulations like GDPR and CCPA.

### 🔍 Key Features

* **Comprehensive Content Scanning**: Automatically scans posts, pages, and active theme files
* **Multiple Data Type Detection**: Identifies emails, phone numbers, API keys, credit cards, SSNs, passwords, JWT tokens, and IP addresses
* **Smart Risk Assessment**: Categorizes findings by risk level (High, Medium, Low) to prioritize remediation
* **Real-time AJAX Scanning**: Fast, non-blocking scans with live progress indicators
* **Clickable Results**: Direct links to edit posts/pages or theme files where issues are found
* **Data Export**: Export scan results to CSV for analysis and reporting
* **Scheduled Scanning**: Set up automatic scans to continuously monitor your site
* **Email Notifications**: Get alerts when high-risk issues are discovered
* **Data Management**: Clean up old results based on retention settings
* **Multilingual Ready**: Fully translatable and i18n compatible

### 🛡️ What It Scans For

**High Risk Data:**
* API Keys and Access Tokens (Generic, AWS, Google, Stripe, GitHub)
* Credit Card Numbers (Visa, Mastercard, Amex, Discover)
* Social Security Numbers (US format)
* Passwords and Secret Keys
* JWT Authentication Tokens

**Medium Risk Data:**
* Email Addresses
* JSON Web Tokens

**Low Risk Data:**
* Phone Numbers (US format)
* IP Addresses

### 🎯 Perfect For

* **Website Administrators** ensuring no sensitive data is accidentally exposed
* **Security Professionals** conducting privacy and security audits
* **Compliance Teams** working to meet GDPR, CCPA, and other privacy regulations
* **Developers** scanning code for accidentally committed secrets
* **WordPress Agencies** managing multiple client websites
* **E-commerce Sites** protecting customer payment information

### 🚀 How It Works

1. **Install and Activate** the plugin through WordPress admin
2. **Configure Settings** to choose what content and data types to scan
3. **Run Quick Scans** with real-time progress and immediate results
4. **Review Findings** in the comprehensive dashboard with risk categorization
5. **Take Action** using direct links to edit problematic content
6. **Export Reports** for documentation and compliance purposes
7. **Set Up Monitoring** with scheduled scans and email alerts

### 🔒 Privacy and Security

This plugin takes your privacy seriously:
* **Local Processing**: All scans are performed locally on your server
* **No External Calls**: No data is sent to external services or APIs
* **Secure Storage**: Scan results are stored securely in your WordPress database
* **User Control**: You have full control over data retention and cleanup
* **WordPress Standards**: Follows WordPress security and coding best practices

### 📊 Professional Dashboard

* **Visual Progress Indicators**: Real-time scan progress with status updates
* **Organized Results Table**: Easy-to-read findings with risk color coding
* **Direct Action Links**: Click to edit posts, pages, or theme files immediately
* **Context Information**: See exactly where sensitive data was found
* **Statistical Overview**: Quick stats on total issues and risk levels
* **Export Functionality**: Download results as CSV for further analysis

== Installation ==

### Automatic Installation

1. Log in to your WordPress admin dashboard
2. Navigate to **Plugins > Add New**
3. Search for "Sensitive Data Scanner"
4. Click **Install Now** and then **Activate**

### Manual Installation

1. Download the plugin ZIP file
2. Upload it via **Plugins > Add New > Upload Plugin**
3. Activate the plugin through the **Plugins** menu in WordPress

### Getting Started

1. Go to **Data Scanner** in your WordPress admin menu
2. Configure your scan settings in the **Settings** tab
3. Click **Start Scan** to run your first comprehensive scan
4. Review the results and take action on any findings
5. Set up scheduled scans for ongoing monitoring

== Frequently Asked Questions ==

= Is my data sent to external servers? =

No, absolutely not. All scanning is performed locally on your WordPress server. No data is ever transmitted to external services, ensuring complete privacy and security.

= How accurate are the scans? =

The plugin uses advanced regex patterns specifically designed to identify sensitive data with high accuracy while minimizing false positives. However, you should always review results manually as automated scanning may occasionally miss edge cases or produce false positives.

= Can I customize what data types to scan for? =

Yes! You can enable or disable specific data types in the settings. You can also configure which content areas to scan (posts, pages, theme files) and set up custom exclude patterns.

= How often should I run scans? =

We recommend running scans:
- **Weekly** for most websites
- **After major content updates** or theme changes
- **Before going live** with new websites
- **Monthly** for sites with infrequent updates

You can also set up automatic scheduled scans for continuous monitoring.

= Will this slow down my website? =

No. The scanning process runs in the admin area only and doesn't affect your website's front-end performance. Scans run in the background and typically complete in under a minute for most sites.

= Can I export the scan results? =

Yes! You can export all scan results to CSV format for further analysis, reporting, or compliance documentation.

= What file types does it scan? =

Currently, the plugin scans:
- **WordPress Content**: Posts and pages (title, content, excerpts)
- **Theme Files**: PHP, JavaScript, and CSS files in your active theme
- **Future Updates**: May include custom post types and additional file types

= How do I remove sensitive data once found? =

The plugin identifies sensitive data but doesn't automatically remove it (for safety). You'll need to:
1. Click the provided links to edit the content or files
2. Manually review and remove or secure the sensitive information
3. Run another scan to verify the issues are resolved

= Is this plugin GDPR compliant? =

The plugin helps you identify potentially GDPR-sensitive data, but compliance depends on how you handle the discovered information. The plugin itself follows privacy best practices by keeping all data local. Consult with legal professionals for specific compliance guidance.

= Can I scan custom post types? =

The current version scans standard posts and pages. Custom post type support may be added in future updates based on user feedback and demand.

== Screenshots ==

1. **Main Dashboard** - Quick scan interface with real-time progress and results overview
2. **Scan Results Table** - Detailed findings with risk levels, context, and direct action links
3. **Settings Page** - Comprehensive configuration options for scan types and data management
4. **Statistics Widget** - Visual overview of scan statistics and risk distribution
5. **Export Features** - CSV export and data management tools

== Changelog ==

= 1.0.0 =
* **Initial Release** - Complete scanning functionality
* **Content Scanning** - Posts, pages, and theme files support
* **Multiple Data Types** - 12 different sensitive data patterns
* **Risk Assessment** - High/Medium/Low risk categorization
* **AJAX Interface** - Real-time scanning with progress indicators
* **Direct Links** - Click to edit problematic content immediately
* **Export Functionality** - CSV export for analysis and reporting
* **Data Management** - Automatic cleanup and retention controls
* **Security Features** - Nonce protection and capability checks
* **Multilingual Support** - Full i18n compatibility with translation template
* **Professional UI** - WordPress-standard admin interface

== Upgrade Notice ==

= 1.0.0 =
Initial release of Sensitive Data Scanner for WordPress. Install now to start protecting your website from accidentally exposed sensitive data and improve your security posture.

== Support ==

**Need Help?**
* **Documentation**: Comprehensive guides and tutorials available


== Privacy Policy ==

This plugin respects your privacy:
* **No External Requests** - All processing happens locally
* **No Data Collection** - We don't collect any usage data or analytics
* **Local Storage Only** - Results stored securely in your WordPress database
* **User Control** - You control all data retention and cleanup settings
