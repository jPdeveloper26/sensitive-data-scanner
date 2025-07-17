<?php
/**
 * Plugin Name: Sensitive Data Scanner
 * Description: Scans posts, pages, and theme files for accidentally exposed sensitive data (emails, API keys, phone numbers, etc.).
 * Version: 1.0.0
 * Author: Juan Mojica
 * Text Domain: sensitive-data-scanner-cognito
 * Domain Path: /languages
 * Requires at least: 5.0
 * Tested up to: 6.2
 * Requires PHP: 7.4
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

if ( ! function_exists( 'cwsdc_wpbay_sdk' ) ) {
    function cwsdc_wpbay_sdk() {
        require_once dirname( __FILE__ ) . '/wpbay-sdk/WPBay_Loader.php';
        $sdk_instance = false;
        global $wpbay_sdk_latest_loader;
        $sdk_loader_class = $wpbay_sdk_latest_loader;
        $sdk_params = array(
            'api_key'                 => 'OIAKDA-LTRHGZK4VP5ZXK3DECZI2OJACI',
            'wpbay_product_id'        => '', 
            'product_file'            => __FILE__,
            'activation_redirect'     => '',
            'is_free'                 => true,
            'is_upgradable'           => false,
            'uploaded_to_wp_org'      => false,
            'disable_feedback'        => false,
            'disable_support_page'    => false,
            'disable_contact_form'    => false,
            'disable_upgrade_form'    => true,
            'disable_analytics'       => false,
            'rating_notice'           => '1 week',
            'debug_mode'              => 'false',
            'no_activation_required'  => false,
            'menu_data'               => array(
                'menu_slug' => ''
            ),
        );
        if ( class_exists( $sdk_loader_class ) ) {
            $sdk_instance = $sdk_loader_class::load_sdk( $sdk_params );
        }
        return $sdk_instance;
    }
    cwsdc_wpbay_sdk();
    do_action( 'cwsdc_wpbay_sdk_loaded' );
}

// Define plugin constants
define('SENSITIVE_DATA_SCANNER_COGNITO_VERSION', '1.0.0');
define('SENSITIVE_DATA_SCANNER_COGNITO_PLUGIN_URL', plugin_dir_url(__FILE__));
define('SENSITIVE_DATA_SCANNER_COGNITO_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('SENSITIVE_DATA_SCANNER_COGNITO_TEXT_DOMAIN', 'sensitive-data-scanner-cognito');

/**
 * Main plugin class
 */
class Sensitive_Data_Scanner_Cognito {
    
    /**
     * Plugin instance
     */
    private static $instance = null;
    
    /**
     * Get plugin instance
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        $this->sensitive_data_scanner_cognito_init();
    }
    
    /**
     * Initialize plugin
     */
    private function sensitive_data_scanner_cognito_init() {
        // Load text domain
        add_action('plugins_loaded', array($this, 'sensitive_data_scanner_cognito_load_textdomain'));
        
        // Include required files
        $this->sensitive_data_scanner_cognito_includes();
        
        // Initialize components
        add_action('init', array($this, 'sensitive_data_scanner_cognito_initialize_components'));
        
        // Plugin activation/deactivation hooks
        register_activation_hook(__FILE__, array($this, 'sensitive_data_scanner_cognito_activate'));
        register_deactivation_hook(__FILE__, array($this, 'sensitive_data_scanner_cognito_deactivate'));
    }
    
    /**
     * Load plugin text domain
     */
    public function sensitive_data_scanner_cognito_load_textdomain() {
        load_plugin_textdomain(
            'SENSITIVE_DATA_SCANNER_COGNITO_TEXT_DOMAIN',
            false,
            dirname(plugin_basename(__FILE__)) . '/languages/'
        );
    }
    
    /**
     * Include required files
     */
    private function sensitive_data_scanner_cognito_includes() {
        // Include admin class
        if (is_admin()) {
            require_once SENSITIVE_DATA_SCANNER_COGNITO_PLUGIN_PATH . 'includes/class-sensitive-data-scanner-cognito-admin.php';
        }
        
        // Include scanner class
        require_once SENSITIVE_DATA_SCANNER_COGNITO_PLUGIN_PATH . 'includes/class-sensitive-data-scanner-cognito-scanner.php';
        
        // Include database class
        require_once SENSITIVE_DATA_SCANNER_COGNITO_PLUGIN_PATH . 'includes/class-sensitive-data-scanner-cognito-database.php';
        
        // Include settings class
        require_once SENSITIVE_DATA_SCANNER_COGNITO_PLUGIN_PATH . 'includes/class-sensitive-data-scanner-cognito-settings.php';
    }
    
    /**
     * Initialize plugin components
     */
    public function sensitive_data_scanner_cognito_initialize_components() {
        if (is_admin()) {
            new Sensitive_Data_Scanner_Cognito_Admin();
        }
        
        new Sensitive_Data_Scanner_Cognito_Scanner();
        new Sensitive_Data_Scanner_Cognito_Database();
        new Sensitive_Data_Scanner_Cognito_Settings();
    }
    
    /**
     * Plugin activation
     */
    public function sensitive_data_scanner_cognito_activate() {
        // Create database tables
        $database = new Sensitive_Data_Scanner_Cognito_Database();
        $database->sensitive_data_scanner_cognito_create_tables();
        
        // Set default options
        $this->sensitive_data_scanner_cognito_set_default_options();
        
        // Flush rewrite rules
        flush_rewrite_rules();
    }
    
    /**
     * Plugin deactivation
     */
    public function sensitive_data_scanner_cognito_deactivate() {
        // Clear scheduled events
        wp_clear_scheduled_hook('sensitive_data_scanner_cognito_scheduled_scan');
        
        // Flush rewrite rules
        flush_rewrite_rules();
    }
    
    /**
     * Set default plugin options
     */
    private function sensitive_data_scanner_cognito_set_default_options() {
        $default_settings = array(
            'scan_posts' => 1,
            'scan_pages' => 1,
            'scan_theme_files' => 1,
            'scan_emails' => 1,
            'scan_api_keys' => 1,
            'scan_phone_numbers' => 1,
            'scan_credit_cards' => 1,
            'scheduled_scan' => 0,
            'scan_frequency' => 'daily'
        );
        
        add_option('sensitive_data_scanner_cognito_settings', $default_settings);
    }
}

// Initialize plugin
Sensitive_Data_Scanner_Cognito::get_instance();
