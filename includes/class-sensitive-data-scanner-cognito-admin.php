<?php
/**
 * Admin functionality for Sensitive Data Scanner
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class Sensitive_Data_Scanner_Cognito_Admin {
    
    /**
     * Constructor
     */
    public function __construct() {
        add_action('admin_menu', array($this, 'sensitive_data_scanner_cognito_add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'sensitive_data_scanner_cognito_enqueue_admin_scripts'));
        add_action('wp_ajax_sensitive_data_scanner_cognito_run_scan', array($this, 'sensitive_data_scanner_cognito_ajax_run_scan'));
        add_action('wp_ajax_sensitive_data_scanner_cognito_clear_results', array($this, 'sensitive_data_scanner_cognito_ajax_clear_results'));
        add_action('admin_notices', array($this, 'sensitive_data_scanner_cognito_admin_notices'));
        
        // Handle form submissions early
        add_action('admin_init', array($this, 'sensitive_data_scanner_cognito_handle_form_submissions'));
    }
    
    /**
     * Handle form submissions
     */
    public function sensitive_data_scanner_cognito_handle_form_submissions() {
        // Only handle on our plugin pages
        if (!isset($_GET['page']) || strpos(sanitize_text_field(wp_unslash($_GET['page'])), 'sensitive-data-scanner-cognito') === false) {
            return;
        }
        
        // Check if we have an action
        if (!isset($_POST['action'])) {
            return;
        }
        
        // Verify nonce - try both possible nonce names
        $nonce_verified = false;
        if (isset($_POST['sensitive_data_scanner_cognito_settings_nonce']) && 
            wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['sensitive_data_scanner_cognito_settings_nonce'])), 'sensitive_data_scanner_cognito_settings_nonce')) {
            $nonce_verified = true;
        } elseif (isset($_POST['sensitive_data_scanner_cognito_nonce']) && 
                  wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['sensitive_data_scanner_cognito_nonce'])), 'sensitive_data_scanner_cognito_nonce')) {
            $nonce_verified = true;
        }
        
        if (!$nonce_verified) {
            wp_die('Security check failed');
            return;
        }
        
        // Check capabilities
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions');
            return;
        }
        
        $action = sanitize_text_field(wp_unslash($_POST['action']));
        
        switch ($action) {
            case 'clear_results':
                $this->sensitive_data_scanner_cognito_handle_clear_results();
                break;
            case 'export_results':
                $this->sensitive_data_scanner_cognito_handle_export_results();
                break;
            case 'cleanup_old_results':
                $this->sensitive_data_scanner_cognito_handle_cleanup_old_results();
                break;
            case 'remove_duplicates':
                $this->sensitive_data_scanner_cognito_handle_remove_duplicates();
                break;
        }
    }
    
    /**
     * Handle clear results action
     */
    private function sensitive_data_scanner_cognito_handle_clear_results() {
        $database = new Sensitive_Data_Scanner_Cognito_Database();
        $result = $database->sensitive_data_scanner_cognito_clear_scan_results();
        
        // Redirect to prevent resubmission
        $redirect_url = remove_query_arg('action');
        $redirect_url = add_query_arg('message', 'cleared', $redirect_url);
        
        wp_safe_redirect($redirect_url);
        exit;
    }
    
    /**
     * Handle export results action
     */
    private function sensitive_data_scanner_cognito_handle_export_results() {
        $database = new Sensitive_Data_Scanner_Cognito_Database();
        $export = $database->sensitive_data_scanner_cognito_export_to_csv();
        
        if ($export) {
            // Force download using WordPress functions
            $file_path = $export['file_path'];
            if (file_exists($file_path)) {
                $file_contents = file_get_contents($file_path);
                if ($file_contents !== false) {
                    header('Content-Type: text/csv');
                    header('Content-Disposition: attachment; filename="' . $export['filename'] . '"');
                    header('Content-Length: ' . strlen($file_contents));
                    echo wp_kses_post($file_contents);
                    wp_delete_file($file_path); // Use WordPress function instead of unlink
                    exit;
                }
            }
        }
        
        // Redirect with error
        $redirect_url = remove_query_arg('action');
        $redirect_url = add_query_arg('message', 'export_failed', $redirect_url);
        
        wp_safe_redirect($redirect_url);
        exit;
    }
    
    /**
     * Handle cleanup old results action
     */
    private function sensitive_data_scanner_cognito_handle_cleanup_old_results() {
        $settings = get_option('sensitive_data_scanner_cognito_settings', array());
        $retention_days = isset($settings['retention_days']) ? $settings['retention_days'] : 30;
        
        $database = new Sensitive_Data_Scanner_Cognito_Database();
        $deleted = $database->sensitive_data_scanner_cognito_cleanup_old_results($retention_days);
        
        // Redirect to prevent resubmission
        $redirect_url = remove_query_arg('action');
        $redirect_url = add_query_arg('message', 'cleaned_' . $deleted, $redirect_url);
        
        wp_safe_redirect($redirect_url);
        exit;
    }
    
    /**
     * Handle remove duplicates action
     */
    private function sensitive_data_scanner_cognito_handle_remove_duplicates() {
        $database = new Sensitive_Data_Scanner_Cognito_Database();
        $deleted = $database->sensitive_data_scanner_cognito_remove_duplicates();
        
        // Redirect to prevent resubmission
        $redirect_url = remove_query_arg('action');
        $redirect_url = add_query_arg('message', 'deduplicated_' . $deleted, $redirect_url);
        
        wp_safe_redirect($redirect_url);
        exit;
    }
    
    /**
     * Add admin menu
     */
    public function sensitive_data_scanner_cognito_add_admin_menu() {
        add_menu_page(
            esc_html__('Sensitive Data Scanner', 'sensitive-data-scanner-cognito'),
            esc_html__('Data Scanner', 'sensitive-data-scanner-cognito'),
            'manage_options',
            'sensitive-data-scanner-cognito',
            array($this, 'sensitive_data_scanner_cognito_admin_page'),
            'dashicons-shield-alt',
            30
        );
        
        add_submenu_page(
            'sensitive-data-scanner-cognito',
            esc_html__('Scan Results', 'sensitive-data-scanner-cognito'),
            esc_html__('Scan Results', 'sensitive-data-scanner-cognito'),
            'manage_options',
            'sensitive-data-scanner-cognito',
            array($this, 'sensitive_data_scanner_cognito_admin_page')
        );
        
        add_submenu_page(
            'sensitive-data-scanner-cognito',
            esc_html__('Settings', 'sensitive-data-scanner-cognito'),
            esc_html__('Settings', 'sensitive-data-scanner-cognito'),
            'manage_options',
            'sensitive-data-scanner-cognito-settings',
            array($this, 'sensitive_data_scanner_cognito_settings_page')
        );
    }
    
    /**
     * Enqueue admin scripts and styles
     */
    public function sensitive_data_scanner_cognito_enqueue_admin_scripts($hook) {
        if (strpos($hook, 'sensitive-data-scanner-cognito') === false) {
            return;
        }
        
        wp_enqueue_style(
            'sensitive-data-scanner-cognito-admin',
            SENSITIVE_DATA_SCANNER_COGNITO_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            SENSITIVE_DATA_SCANNER_COGNITO_VERSION
        );
        
        wp_enqueue_script(
            'sensitive-data-scanner-cognito-admin',
            SENSITIVE_DATA_SCANNER_COGNITO_PLUGIN_URL . 'assets/js/admin.js',
            array('jquery'),
            SENSITIVE_DATA_SCANNER_COGNITO_VERSION,
            true
        );
        
        wp_localize_script('sensitive-data-scanner-cognito-admin', 'sensitiveDataScannerCognito', array(
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('sensitive_data_scanner_cognito_nonce'),
            'strings' => array(
                'scanning' => esc_html__('Scanning...', 'sensitive-data-scanner-cognito'),
                'scan_complete' => esc_html__('Scan complete!', 'sensitive-data-scanner-cognito'),
                'scan_error' => esc_html__('Scan failed. Please try again.', 'sensitive-data-scanner-cognito'),
                'confirm_clear' => esc_html__('Are you sure you want to clear all scan results?', 'sensitive-data-scanner-cognito')
            )
        ));
    }
    
    /**
     * Main admin page
     */
    public function sensitive_data_scanner_cognito_admin_page() {
        // Handle form submissions directly here for testing
        if (isset($_POST['action']) && isset($_POST['sensitive_data_scanner_cognito_settings_nonce']) && 
            wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['sensitive_data_scanner_cognito_settings_nonce'])), 'sensitive_data_scanner_cognito_settings_nonce')) {
            
            $action = sanitize_text_field(wp_unslash($_POST['action']));
            
            if ($action === 'clear_results') {
                $database = new Sensitive_Data_Scanner_Cognito_Database();
                $result = $database->sensitive_data_scanner_cognito_clear_scan_results();
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('All scan results have been cleared.', 'sensitive-data-scanner-cognito') . '</p></div>';
            }
        }
        
        // Show messages
        $this->sensitive_data_scanner_cognito_show_messages();
        
        // Get scan results
        $database = new Sensitive_Data_Scanner_Cognito_Database();
        $results = $database->sensitive_data_scanner_cognito_get_scan_results();
        
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Sensitive Data Scanner', 'sensitive-data-scanner-cognito'); ?></h1>
            
            <div class="sensitive-data-scanner-cognito-dashboard">
                <div class="postbox">
                    <h2 class="hndle"><?php echo esc_html__('Quick Scan', 'sensitive-data-scanner-cognito'); ?></h2>
                    <div class="inside">
                        <p><?php echo esc_html__('Start a comprehensive scan of your website for sensitive data.', 'sensitive-data-scanner-cognito'); ?></p>
                        <button type="button" class="button button-primary button-large" id="run-scan-btn">
                            <?php echo esc_html__('Start Scan', 'sensitive-data-scanner-cognito'); ?>
                        </button>
                        <div id="scan-progress" style="display: none;">
                            <div class="progress-bar">
                                <div class="progress-fill"></div>
                            </div>
                            <p id="scan-status"><?php echo esc_html__('Initializing scan...', 'sensitive-data-scanner-cognito'); ?></p>
                        </div>
                    </div>
                </div>
                
                <div class="postbox">
                    <h2 class="hndle"><?php echo esc_html__('Scan Results', 'sensitive-data-scanner-cognito'); ?></h2>
                    <div class="inside">
                        <?php if (empty($results)): ?>
                            <p><?php echo esc_html__('No scan results found. Run a scan to see results here.', 'sensitive-data-scanner-cognito'); ?></p>
                        <?php else: ?>
                            <div class="scan-results-controls">
                                <form method="post" action="" style="display: inline;">
                                    <?php wp_nonce_field('sensitive_data_scanner_cognito_settings_nonce', 'sensitive_data_scanner_cognito_settings_nonce'); ?>
                                    <input type="hidden" name="action" value="clear_results">
                                    <button type="submit" class="button button-secondary" onclick="return confirm('<?php echo esc_js(__('Are you sure you want to clear all scan results?', 'sensitive-data-scanner-cognito')); ?>')">
                                        <?php echo esc_html__('Clear All Results', 'sensitive-data-scanner-cognito'); ?>
                                    </button>
                                </form>
                                <span class="results-count">
                                    <?php 
                                    /* translators: %d: number of results */
                                    echo esc_html(sprintf(__('%d issues found', 'sensitive-data-scanner-cognito'), count($results))); 
                                    ?>
                                </span>
                            </div>
                            
                            <table class="wp-list-table widefat fixed striped">
                                <thead>
                                    <tr>
                                        <th><?php echo esc_html__('Location', 'sensitive-data-scanner-cognito'); ?></th>
                                        <th><?php echo esc_html__('Type', 'sensitive-data-scanner-cognito'); ?></th>
                                        <th><?php echo esc_html__('Data Found', 'sensitive-data-scanner-cognito'); ?></th>
                                        <th><?php echo esc_html__('Context', 'sensitive-data-scanner-cognito'); ?></th>
                                        <th><?php echo esc_html__('Risk Level', 'sensitive-data-scanner-cognito'); ?></th>
                                        <th><?php echo esc_html__('Date Found', 'sensitive-data-scanner-cognito'); ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($results as $result): ?>
                                        <tr>
                                            <td>
                                                <?php if ($result->location_id && in_array($result->location_type, array('Post', 'Page'))): ?>
                                                    <strong>
                                                        <a href="<?php echo esc_url(get_edit_post_link($result->location_id)); ?>" target="_blank">
                                                            <?php echo esc_html($result->location_type . ': ' . $result->location_name); ?>
                                                            <span class="dashicons dashicons-external" style="font-size: 12px; margin-left: 3px;"></span>
                                                        </a>
                                                    </strong>
                                                    <br>
                                                    <small>
                                                        <?php echo esc_html__('ID:', 'sensitive-data-scanner-cognito') . ' ' . esc_html($result->location_id); ?>
                                                        | 
                                                        <a href="<?php echo esc_url(get_permalink($result->location_id)); ?>" target="_blank">
                                                            <?php echo esc_html__('View', 'sensitive-data-scanner-cognito'); ?>
                                                        </a>
                                                    </small>
                                                <?php elseif ($result->location_type === 'Theme File'): ?>
                                                    <strong><?php echo esc_html($result->location_type . ': ' . $result->location_name); ?></strong>
                                                    <br>
                                                    <small>
                                                        <?php 
                                                        $theme_info = wp_get_theme();
                                                        echo esc_html__('Theme:', 'sensitive-data-scanner-cognito') . ' ' . esc_html($theme_info->get('Name')); 
                                                        ?>
                                                        | 
                                                        <a href="<?php echo esc_url(admin_url('theme-editor.php?file=' . urlencode($result->location_name))); ?>" target="_blank">
                                                            <?php echo esc_html__('Edit File', 'sensitive-data-scanner-cognito'); ?>
                                                        </a>
                                                    </small>
                                                <?php else: ?>
                                                    <strong><?php echo esc_html($result->location_type . ': ' . $result->location_name); ?></strong>
                                                    <?php if ($result->location_id): ?>
                                                        <br><small><?php echo esc_html__('ID:', 'sensitive-data-scanner-cognito') . ' ' . esc_html($result->location_id); ?></small>
                                                    <?php endif; ?>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <span class="data-type-badge data-type-<?php echo esc_attr(strtolower($result->data_type)); ?>">
                                                    <?php echo esc_html($result->data_type); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <code><?php echo esc_html($this->sensitive_data_scanner_cognito_mask_sensitive_data($result->data_found, $result->data_type)); ?></code>
                                            </td>
                                            <td>
                                                <?php if (!empty($result->context)): ?>
                                                    <small style="font-style: italic; color: #666;">
                                                        <?php echo esc_html($result->context); ?>
                                                    </small>
                                                <?php else: ?>
                                                    <span style="color: #999;">—</span>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <span class="risk-level risk-level-<?php echo esc_attr(strtolower($result->risk_level)); ?>">
                                                    <?php echo esc_html($result->risk_level); ?>
                                                </span>
                                            </td>
                                            <td><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($result->created_at))); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    
    /**
     * Settings page
     */
    public function sensitive_data_scanner_cognito_settings_page() {
        $settings = new Sensitive_Data_Scanner_Cognito_Settings();
        $settings->sensitive_data_scanner_cognito_render_settings_page();
    }
    
    /**
     * AJAX handler for running scan
     */
    public function sensitive_data_scanner_cognito_ajax_run_scan() {
        // Verify nonce
        if (!check_ajax_referer('sensitive_data_scanner_cognito_nonce', 'nonce', false)) {
            wp_send_json_error(array(
                'message' => esc_html__('Security check failed.', 'sensitive-data-scanner-cognito')
            ));
        }
        
        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array(
                'message' => esc_html__('You do not have sufficient permissions to access this page.', 'sensitive-data-scanner-cognito')
            ));
        }
        
        try {
            $scanner = new Sensitive_Data_Scanner_Cognito_Scanner();
            $results = $scanner->sensitive_data_scanner_cognito_run_full_scan();
            
            wp_send_json_success(array(
                'status' => 'completed',
                'message' => esc_html__('Scan completed successfully!', 'sensitive-data-scanner-cognito'),
                'results_count' => count($results),
                'high_risk_count' => $this->sensitive_data_scanner_cognito_count_high_risk($results)
            ));
        } catch (Exception $e) {
            wp_send_json_error(array(
                'message' => esc_html__('Scan failed: ', 'sensitive-data-scanner-cognito') . $e->getMessage()
            ));
        }
    }
    
    /**
     * Count high risk results
     */
    private function sensitive_data_scanner_cognito_count_high_risk($results) {
        $high_risk_count = 0;
        foreach ($results as $result) {
            if (isset($result['risk_level']) && $result['risk_level'] === 'High') {
                $high_risk_count++;
            }
        }
        return $high_risk_count;
    }
    
    /**
     * Show admin messages
     * 
     * Displays status messages from URL parameters after redirects.
     * This is safe as it only displays predefined messages and doesn't 
     * perform any sensitive operations based on user input.
     * 
     * Nonce verification is not required here because:
     * 1. This is a read-only operation that only displays status messages
     * 2. No sensitive data is accessed or modified
     * 3. Only predefined message types are processed
     * 4. All input is properly sanitized before use
     */
    private function sensitive_data_scanner_cognito_show_messages() {
       
        if (isset($_GET['message'])) {
			 // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Safe read-only status message display
            $message = sanitize_text_field(wp_unslash($_GET['message']));
            
            switch ($message) {
                case 'cleared':
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('All scan results have been cleared.', 'sensitive-data-scanner-cognito') . '</p></div>';
                    break;
                case 'export_failed':
                    echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('Export failed. Please try again.', 'sensitive-data-scanner-cognito') . '</p></div>';
                    break;
                default:
                    // Handle other message patterns like 'cleaned_X' or 'deduplicated_X'
                    if (strpos($message, 'cleaned_') === 0) {
                        $count = intval(str_replace('cleaned_', '', $message));
                        echo '<div class="notice notice-success is-dismissible"><p>' . 
                             sprintf(
                                 /* translators: %d: number of deleted records */
                                 esc_html__('Cleaned up %d old scan results.', 'sensitive-data-scanner-cognito'),
                                 wp_kses_post($count)
                             ) . '</p></div>';
                    } elseif (strpos($message, 'deduplicated_') === 0) {
                        $count = intval(str_replace('deduplicated_', '', $message));
                        echo '<div class="notice notice-success is-dismissible"><p>' . 
                             sprintf(
                                 /* translators: %d: number of deleted duplicates */
                                 esc_html__('Removed %d duplicate scan results.', 'sensitive-data-scanner-cognito'),
                                 wp_kses_post($count)
                             ) . '</p></div>';
                    }
                    break;
            }
        }
    }
    
    /**
     * AJAX handler for clearing results
     */
    public function sensitive_data_scanner_cognito_ajax_clear_results() {
        // Verify nonce
        if (!check_ajax_referer('sensitive_data_scanner_cognito_nonce', 'nonce', false)) {
            wp_send_json_error(array(
                'message' => esc_html__('Security check failed.', 'sensitive-data-scanner-cognito')
            ));
        }
        
        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array(
                'message' => esc_html__('You do not have sufficient permissions to access this page.', 'sensitive-data-scanner-cognito')
            ));
        }
        
        try {
            $database = new Sensitive_Data_Scanner_Cognito_Database();
            $database->sensitive_data_scanner_cognito_clear_scan_results();
            
            wp_send_json_success(array(
                'message' => esc_html__('All scan results have been cleared.', 'sensitive-data-scanner-cognito')
            ));
        } catch (Exception $e) {
            wp_send_json_error(array(
                'message' => esc_html__('Failed to clear results: ', 'sensitive-data-scanner-cognito') . $e->getMessage()
            ));
        }
    }
    
    /**
     * Show admin notices
     */
    public function sensitive_data_scanner_cognito_admin_notices() {
        $database = new Sensitive_Data_Scanner_Cognito_Database();
        $results = $database->sensitive_data_scanner_cognito_get_scan_results();
        
        if (!empty($results)) {
            $high_risk_count = 0;
            foreach ($results as $result) {
                if ($result->risk_level === 'High') {
                    $high_risk_count++;
                }
            }
            
            if ($high_risk_count > 0) {
                ?>
                <div class="notice notice-warning">
                    <p>
                        <?php 
                        /* translators: %d: number of high-risk issues */
                        echo esc_html(sprintf(__('Sensitive Data Scanner found %d high-risk issues on your website.', 'sensitive-data-scanner-cognito'), $high_risk_count)); 
                        ?>
                        <a href="<?php echo esc_url(admin_url('admin.php?page=sensitive-data-scanner-cognito')); ?>">
                            <?php echo esc_html__('View Details', 'sensitive-data-scanner-cognito'); ?>
                        </a>
                    </p>
                </div>
                <?php
            }
        }
    }
    
    /**
     * Mask sensitive data for display
     */
    private function sensitive_data_scanner_cognito_mask_sensitive_data($data, $type) {
        switch (strtolower($type)) {
            case 'email':
                return preg_replace('/(.{2}).*(@.*)/', '$1***$2', $data);
            case 'phone':
                return preg_replace('/(\d{3})[\d\-\s]*(\d{4})/', '$1***$2', $data);
            case 'api_key':
            case 'credit_card':
                return substr($data, 0, 4) . str_repeat('*', strlen($data) - 8) . substr($data, -4);
            default:
                return substr($data, 0, 10) . '...';
        }
    }
}