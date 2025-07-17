<?php
/**
 * Uninstall script for Sensitive Data Scanner
 * 
 * This file is executed when the plugin is deleted via WordPress admin.
 * It removes all plugin data from the database.
 */

// Prevent direct access
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Include the database class
require_once plugin_dir_path(__FILE__) . 'includes/class-sensitive-data-scanner-cognito-database.php';

/**
 * Remove all plugin data
 */
function sensitive_data_scanner_cognito_uninstall() {
    // Remove database tables
    $database = new Sensitive_Data_Scanner_Cognito_Database();
    $database->sensitive_data_scanner_cognito_drop_tables();
    
    // Remove plugin options
    delete_option('sensitive_data_scanner_cognito_settings');
    delete_option('sensitive_data_scanner_cognito_db_version');
    
    // Clear scheduled events
    wp_clear_scheduled_hook('sensitive_data_scanner_cognito_scheduled_scan');
    
    // Remove any uploaded export files
    $upload_dir = wp_upload_dir();
    $files = glob($upload_dir['basedir'] . '/sensitive-data-scan-*.csv');
    
    if ($files) {
        foreach ($files as $file) {
            if (is_file($file)) {
                wp_delete_file($file);
            }
        }
    }
    
    // Remove user meta data
    delete_metadata('user', 0, 'sensitive_data_scanner_cognito_dismissed_notices', '', true);
    
    // Remove transients
    delete_transient('sensitive_data_scanner_cognito_scan_progress');
    delete_transient('sensitive_data_scanner_cognito_last_scan');
}

// Execute uninstall
sensitive_data_scanner_cognito_uninstall();