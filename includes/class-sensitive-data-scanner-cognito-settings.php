<?php
/**
 * Settings functionality for Sensitive Data Scanner
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class Sensitive_Data_Scanner_Cognito_Settings {
    
    /**
     * Settings option name
     */
    private $option_name = 'sensitive_data_scanner_cognito_settings';
    
    /**
     * Constructor
     */
    public function __construct() {
        add_action('admin_init', array($this, 'sensitive_data_scanner_cognito_register_settings'));
    }
    
    /**
     * Register settings
     */
    public function sensitive_data_scanner_cognito_register_settings() {
        register_setting(
            'sensitive_data_scanner_cognito_settings_group',
            $this->option_name,
            array($this, 'sensitive_data_scanner_cognito_sanitize_settings')
        );
        
        // Scan Options Section
        add_settings_section(
            'sensitive_data_scanner_cognito_scan_options',
            esc_html__('Scan Options', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_scan_options_callback'),
            'sensitive_data_scanner_cognito_settings'
        );
        
        // Data Types Section
        add_settings_section(
            'sensitive_data_scanner_cognito_data_types',
            esc_html__('Data Types to Scan', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_data_types_callback'),
            'sensitive_data_scanner_cognito_settings'
        );
        
        // Scheduling Section
        add_settings_section(
            'sensitive_data_scanner_cognito_scheduling',
            esc_html__('Scheduled Scans', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_scheduling_callback'),
            'sensitive_data_scanner_cognito_settings'
        );
        
        // Advanced Section
        add_settings_section(
            'sensitive_data_scanner_cognito_advanced',
            esc_html__('Advanced Options', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_advanced_callback'),
            'sensitive_data_scanner_cognito_settings'
        );
        
        $this->sensitive_data_scanner_cognito_add_settings_fields();
    }
    
    /**
     * Add settings fields
     */
    private function sensitive_data_scanner_cognito_add_settings_fields() {
        // Scan Options Fields
        add_settings_field(
            'scan_posts',
            esc_html__('Scan Posts', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_checkbox_field'),
            'sensitive_data_scanner_cognito_settings',
            'sensitive_data_scanner_cognito_scan_options',
            array(
                'field' => 'scan_posts',
                'description' => esc_html__('Include published posts in scans', 'sensitive-data-scanner-cognito')
            )
        );
        
        add_settings_field(
            'scan_pages',
            esc_html__('Scan Pages', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_checkbox_field'),
            'sensitive_data_scanner_cognito_settings',
            'sensitive_data_scanner_cognito_scan_options',
            array(
                'field' => 'scan_pages',
                'description' => esc_html__('Include published pages in scans', 'sensitive-data-scanner-cognito')
            )
        );
        
        add_settings_field(
            'scan_theme_files',
            esc_html__('Scan Theme Files', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_checkbox_field'),
            'sensitive_data_scanner_cognito_settings',
            'sensitive_data_scanner_cognito_scan_options',
            array(
                'field' => 'scan_theme_files',
                'description' => esc_html__('Include active theme files in scans (PHP, JS, CSS)', 'sensitive-data-scanner-cognito')
            )
        );
        
        // Data Types Fields
        $data_types = array(
            'scan_emails' => array(
                'label' => esc_html__('Email Addresses', 'sensitive-data-scanner-cognito'),
                'description' => esc_html__('Scan for email addresses', 'sensitive-data-scanner-cognito')
            ),
            'scan_phone_numbers' => array(
                'label' => esc_html__('Phone Numbers', 'sensitive-data-scanner-cognito'),
                'description' => esc_html__('Scan for phone numbers', 'sensitive-data-scanner-cognito')
            ),
            'scan_api_keys' => array(
                'label' => esc_html__('API Keys', 'sensitive-data-scanner-cognito'),
                'description' => esc_html__('Scan for API keys and access tokens', 'sensitive-data-scanner-cognito')
            ),
            'scan_credit_cards' => array(
                'label' => esc_html__('Credit Card Numbers', 'sensitive-data-scanner-cognito'),
                'description' => esc_html__('Scan for credit card numbers', 'sensitive-data-scanner-cognito')
            ),
            'scan_ssn' => array(
                'label' => esc_html__('Social Security Numbers', 'sensitive-data-scanner-cognito'),
                'description' => esc_html__('Scan for Social Security Numbers (US)', 'sensitive-data-scanner-cognito')
            ),
            'scan_passwords' => array(
                'label' => esc_html__('Passwords', 'sensitive-data-scanner-cognito'),
                'description' => esc_html__('Scan for password patterns', 'sensitive-data-scanner-cognito')
            ),
            'scan_jwt_tokens' => array(
                'label' => esc_html__('JWT Tokens', 'sensitive-data-scanner-cognito'),
                'description' => esc_html__('Scan for JSON Web Tokens', 'sensitive-data-scanner-cognito')
            ),
            'scan_ip_addresses' => array(
                'label' => esc_html__('IP Addresses', 'sensitive-data-scanner-cognito'),
                'description' => esc_html__('Scan for IP addresses', 'sensitive-data-scanner-cognito')
            )
        );
        
        foreach ($data_types as $field => $config) {
            add_settings_field(
                $field,
                $config['label'],
                array($this, 'sensitive_data_scanner_cognito_checkbox_field'),
                'sensitive_data_scanner_cognito_settings',
                'sensitive_data_scanner_cognito_data_types',
                array(
                    'field' => $field,
                    'description' => $config['description']
                )
            );
        }
        
        // Scheduling Fields
        add_settings_field(
            'scheduled_scan',
            esc_html__('Enable Scheduled Scans', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_checkbox_field'),
            'sensitive_data_scanner_cognito_settings',
            'sensitive_data_scanner_cognito_scheduling',
            array(
                'field' => 'scheduled_scan',
                'description' => esc_html__('Automatically run scans on a schedule', 'sensitive-data-scanner-cognito')
            )
        );
        
        add_settings_field(
            'scan_frequency',
            esc_html__('Scan Frequency', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_select_field'),
            'sensitive_data_scanner_cognito_settings',
            'sensitive_data_scanner_cognito_scheduling',
            array(
                'field' => 'scan_frequency',
                'options' => array(
                    'hourly' => esc_html__('Hourly', 'sensitive-data-scanner-cognito'),
                    'twicedaily' => esc_html__('Twice Daily', 'sensitive-data-scanner-cognito'),
                    'daily' => esc_html__('Daily', 'sensitive-data-scanner-cognito'),
                    'weekly' => esc_html__('Weekly', 'sensitive-data-scanner-cognito')
                ),
                'description' => esc_html__('How often to run scheduled scans', 'sensitive-data-scanner-cognito')
            )
        );
        
        add_settings_field(
            'email_notifications',
            esc_html__('Email Notifications', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_checkbox_field'),
            'sensitive_data_scanner_cognito_settings',
            'sensitive_data_scanner_cognito_scheduling',
            array(
                'field' => 'email_notifications',
                'description' => esc_html__('Send email notifications when high-risk issues are found', 'sensitive-data-scanner-cognito')
            )
        );
        
        // Advanced Fields
        add_settings_field(
            'retention_days',
            esc_html__('Data Retention (Days)', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_number_field'),
            'sensitive_data_scanner_cognito_settings',
            'sensitive_data_scanner_cognito_advanced',
            array(
                'field' => 'retention_days',
                'min' => 1,
                'max' => 365,
                'default' => 30,
                'description' => esc_html__('Number of days to keep scan results before automatic cleanup', 'sensitive-data-scanner-cognito')
            )
        );
        
        add_settings_field(
            'exclude_patterns',
            esc_html__('Exclude Patterns', 'sensitive-data-scanner-cognito'),
            array($this, 'sensitive_data_scanner_cognito_textarea_field'),
            'sensitive_data_scanner_cognito_settings',
            'sensitive_data_scanner_cognito_advanced',
            array(
                'field' => 'exclude_patterns',
                'description' => esc_html__('One pattern per line. Use regex patterns to exclude specific content from scans.', 'sensitive-data-scanner-cognito')
            )
        );
    }
    
    /**
     * Section callbacks
     */
    public function sensitive_data_scanner_cognito_scan_options_callback() {
        echo '<p>' . esc_html__('Configure what content to include in your scans.', 'sensitive-data-scanner-cognito') . '</p>';
    }
    
    public function sensitive_data_scanner_cognito_data_types_callback() {
        echo '<p>' . esc_html__('Select which types of sensitive data to scan for.', 'sensitive-data-scanner-cognito') . '</p>';
    }
    
    public function sensitive_data_scanner_cognito_scheduling_callback() {
        echo '<p>' . esc_html__('Configure automatic scheduled scans and notifications.', 'sensitive-data-scanner-cognito') . '</p>';
    }
    
    public function sensitive_data_scanner_cognito_advanced_callback() {
        echo '<p>' . esc_html__('Advanced configuration options for power users.', 'sensitive-data-scanner-cognito') . '</p>';
    }
    
    /**
     * Field callbacks
     */
    public function sensitive_data_scanner_cognito_checkbox_field($args) {
        $settings = get_option($this->option_name, array());
        $value = isset($settings[$args['field']]) ? $settings[$args['field']] : 0;
        
        echo '<label for="' . esc_attr($args['field']) . '">';
        echo '<input type="checkbox" id="' . esc_attr($args['field']) . '" name="' . esc_attr($this->option_name) . '[' . esc_attr($args['field']) . ']" value="1" ' . checked(1, $value, false) . ' />';
        echo ' ' . esc_html($args['description']);
        echo '</label>';
    }
    
    public function sensitive_data_scanner_cognito_select_field($args) {
        $settings = get_option($this->option_name, array());
        $value = isset($settings[$args['field']]) ? $settings[$args['field']] : '';
        
        echo '<select id="' . esc_attr($args['field']) . '" name="' . esc_attr($this->option_name) . '[' . esc_attr($args['field']) . ']">';
        foreach ($args['options'] as $option_value => $option_label) {
            echo '<option value="' . esc_attr($option_value) . '" ' . selected($value, $option_value, false) . '>';
            echo esc_html($option_label);
            echo '</option>';
        }
        echo '</select>';
        
        if (isset($args['description'])) {
            echo '<p class="description">' . esc_html($args['description']) . '</p>';
        }
    }
    
    public function sensitive_data_scanner_cognito_number_field($args) {
        $settings = get_option($this->option_name, array());
        $value = isset($settings[$args['field']]) ? $settings[$args['field']] : $args['default'];
        
        echo '<input type="number" id="' . esc_attr($args['field']) . '" name="' . esc_attr($this->option_name) . '[' . esc_attr($args['field']) . ']" value="' . esc_attr($value) . '"';
        
        if (isset($args['min'])) {
            echo ' min="' . esc_attr($args['min']) . '"';
        }
        
        if (isset($args['max'])) {
            echo ' max="' . esc_attr($args['max']) . '"';
        }
        
        echo ' class="small-text" />';
        
        if (isset($args['description'])) {
            echo '<p class="description">' . esc_html($args['description']) . '</p>';
        }
    }
    
    public function sensitive_data_scanner_cognito_textarea_field($args) {
        $settings = get_option($this->option_name, array());
        $value = isset($settings[$args['field']]) ? $settings[$args['field']] : '';
        
        echo '<textarea id="' . esc_attr($args['field']) . '" name="' . esc_attr($this->option_name) . '[' . esc_attr($args['field']) . ']" rows="5" cols="50" class="large-text">';
        echo esc_textarea($value);
        echo '</textarea>';
        
        if (isset($args['description'])) {
            echo '<p class="description">' . esc_html($args['description']) . '</p>';
        }
    }
    
    /**
     * Sanitize settings
     */
    public function sensitive_data_scanner_cognito_sanitize_settings($input) {
        $sanitized = array();
        
        // Checkbox fields
        $checkbox_fields = array(
            'scan_posts', 'scan_pages', 'scan_theme_files',
            'scan_emails', 'scan_phone_numbers', 'scan_api_keys', 'scan_credit_cards',
            'scan_ssn', 'scan_passwords', 'scan_jwt_tokens', 'scan_ip_addresses',
            'scheduled_scan', 'email_notifications'
        );
        
        foreach ($checkbox_fields as $field) {
            $sanitized[$field] = isset($input[$field]) ? 1 : 0;
        }
        
        // Select fields
        if (isset($input['scan_frequency'])) {
            $allowed_frequencies = array('hourly', 'twicedaily', 'daily', 'weekly');
            $sanitized['scan_frequency'] = in_array($input['scan_frequency'], $allowed_frequencies) ? $input['scan_frequency'] : 'daily';
        }
        
        // Number fields
        if (isset($input['retention_days'])) {
            $sanitized['retention_days'] = max(1, min(365, intval($input['retention_days'])));
        }
        
        // Textarea fields
        if (isset($input['exclude_patterns'])) {
            $sanitized['exclude_patterns'] = sanitize_textarea_field($input['exclude_patterns']);
        }
        
        // Handle scheduling changes
        $old_settings = get_option($this->option_name, array());
        if (isset($old_settings['scheduled_scan']) && $old_settings['scheduled_scan'] != $sanitized['scheduled_scan']) {
            $scanner = new Sensitive_Data_Scanner_Cognito_Scanner();
            
            if ($sanitized['scheduled_scan']) {
                $frequency = isset($sanitized['scan_frequency']) ? $sanitized['scan_frequency'] : 'daily';
                $scanner->sensitive_data_scanner_cognito_schedule_scan($frequency);
            } else {
                $scanner->sensitive_data_scanner_cognito_unschedule_scan();
            }
        }
        
        return $sanitized;
    }
    
    /**
     * Render settings page
     */
    public function sensitive_data_scanner_cognito_render_settings_page() {
        // Handle form submission
        if (isset($_POST['submit']) && check_admin_referer('sensitive_data_scanner_cognito_settings_nonce', 'sensitive_data_scanner_cognito_settings_nonce')) {
            // Settings are automatically saved by WordPress settings API
            echo '<div class="notice notice-success"><p>' . esc_html__('Settings saved successfully!', 'sensitive-data-scanner-cognito') . '</p></div>';
        }
        
        // Handle action forms directly
        if (isset($_POST['action']) && isset($_POST['sensitive_data_scanner_cognito_settings_nonce']) && 
            wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['sensitive_data_scanner_cognito_settings_nonce'])), 'sensitive_data_scanner_cognito_settings_nonce')) {
            
            $action = sanitize_text_field(wp_unslash($_POST['action']));
            
            switch ($action) {
                case 'clear_results':
                    $database = new Sensitive_Data_Scanner_Cognito_Database();
                    $database->sensitive_data_scanner_cognito_clear_scan_results();
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('All scan results have been cleared.', 'sensitive-data-scanner-cognito') . '</p></div>';
                    break;
                    
                case 'export_results':
                    $database = new Sensitive_Data_Scanner_Cognito_Database();
                    $export = $database->sensitive_data_scanner_cognito_export_to_csv();
                    
                    if ($export && file_exists($export['file_path'])) {
                        // Force download using WordPress filesystem methods
                        $file_contents = file_get_contents($export['file_path']);
                        if ($file_contents !== false) {
                            header('Content-Type: text/csv');
                            header('Content-Disposition: attachment; filename="' . $export['filename'] . '"');
                            header('Content-Length: ' . strlen($file_contents));
                            echo wp_kses_post($file_contents);
                            wp_delete_file($export['file_path']); // Use WordPress function instead of unlink
                            exit;
                        }
                    } else {
                        echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('Export failed. Please try again.', 'sensitive-data-scanner-cognito') . '</p></div>';
                    }
                    break;
                    
                case 'cleanup_old_results':
                    $settings = get_option($this->option_name, array());
                    $retention_days = isset($settings['retention_days']) ? $settings['retention_days'] : 30;
                    
                    $database = new Sensitive_Data_Scanner_Cognito_Database();
                    $deleted = $database->sensitive_data_scanner_cognito_cleanup_old_results($retention_days);
                    
                    echo '<div class="notice notice-success is-dismissible"><p>' . 
                         sprintf(
                             /* translators: %d: number of deleted records */
                             esc_html__('Cleaned up %d old scan results.', 'sensitive-data-scanner-cognito'),
                             wp_kses_post($deleted)
                         ) . '</p></div>';
                    break;
            }
        }
        
        // Show success/error messages from redirects
        if (isset($_GET['message'])) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
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
        
        // Get statistics
        $database = new Sensitive_Data_Scanner_Cognito_Database();
        $stats = $database->sensitive_data_scanner_cognito_get_statistics();
        
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Sensitive Data Scanner Settings', 'sensitive-data-scanner-cognito'); ?></h1>
            
            <div class="sensitive-data-scanner-cognito-settings">
                <div class="settings-grid">
                    <div class="settings-main">
                        <form method="post" action="options.php">
                            <?php
                            settings_fields('sensitive_data_scanner_cognito_settings_group');
                            do_settings_sections('sensitive_data_scanner_cognito_settings');
                            wp_nonce_field('sensitive_data_scanner_cognito_settings_nonce', 'sensitive_data_scanner_cognito_settings_nonce');
                            submit_button();
                            ?>
                        </form>
                    </div>
                    
                    <div class="settings-sidebar">
                        <!-- Statistics Widget -->
                        <div class="postbox">
                            <h2 class="hndle"><?php echo esc_html__('Scan Statistics', 'sensitive-data-scanner-cognito'); ?></h2>
                            <div class="inside">
                                <div class="stats-grid">
                                    <div class="stat-item">
                                        <span class="stat-number"><?php echo esc_html($stats['total']); ?></span>
                                        <span class="stat-label"><?php echo esc_html__('Total Issues', 'sensitive-data-scanner-cognito'); ?></span>
                                    </div>
                                    
                                    <?php if (isset($stats['by_risk_level']['high'])): ?>
                                    <div class="stat-item risk-high">
                                        <span class="stat-number"><?php echo esc_html($stats['by_risk_level']['high']); ?></span>
                                        <span class="stat-label"><?php echo esc_html__('High Risk', 'sensitive-data-scanner-cognito'); ?></span>
                                    </div>
                                    <?php endif; ?>
                                    
                                    <?php if (isset($stats['by_risk_level']['medium'])): ?>
                                    <div class="stat-item risk-medium">
                                        <span class="stat-number"><?php echo esc_html($stats['by_risk_level']['medium']); ?></span>
                                        <span class="stat-label"><?php echo esc_html__('Medium Risk', 'sensitive-data-scanner-cognito'); ?></span>
                                    </div>
                                    <?php endif; ?>
                                    
                                    <?php if (isset($stats['by_risk_level']['low'])): ?>
                                    <div class="stat-item risk-low">
                                        <span class="stat-number"><?php echo esc_html($stats['by_risk_level']['low']); ?></span>
                                        <span class="stat-label"><?php echo esc_html__('Low Risk', 'sensitive-data-scanner-cognito'); ?></span>
                                    </div>
                                    <?php endif; ?>
                                </div>
                                
                                <?php if ($stats['last_scan']): ?>
                                <p class="last-scan">
                                    <?php 
                                    echo esc_html__('Last scan:', 'sensitive-data-scanner-cognito') . ' ';
                                    echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($stats['last_scan'])));
                                    ?>
                                </p>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <!-- Data Management Widget -->
                        <div class="postbox">
                            <h2 class="hndle"><?php echo esc_html__('Data Management', 'sensitive-data-scanner-cognito'); ?></h2>
                            <div class="inside">
                                <form method="post" action="">
                                    <?php wp_nonce_field('sensitive_data_scanner_cognito_settings_nonce', 'sensitive_data_scanner_cognito_settings_nonce'); ?>
                                    
                                    <p>
                                        <input type="hidden" name="action" value="export_results">
                                        <button type="submit" class="button button-secondary">
                                            <?php echo esc_html__('Export Results to CSV', 'sensitive-data-scanner-cognito'); ?>
                                        </button>
                                    </p>
                                </form>
                                
                                <form method="post" action="" style="display: none !important;">
                                    <?php wp_nonce_field('sensitive_data_scanner_cognito_settings_nonce', 'sensitive_data_scanner_cognito_settings_nonce'); ?>
                                    
                                    <p>
                                        <input type="hidden" name="action" value="cleanup_old_results">
                                        <button type="submit" class="button button-secondary" onclick="return confirm('<?php echo esc_js(__('Are you sure you want to clean up old scan results?', 'sensitive-data-scanner-cognito')); ?>')">
                                            <?php echo esc_html__('Clean Up Old Results', 'sensitive-data-scanner-cognito'); ?>
                                        </button>
                                    </p>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    
    /**
     * Get default settings
     */
    public function sensitive_data_scanner_cognito_get_default_settings() {
        return array(
            'scan_posts' => 1,
            'scan_pages' => 1,
            'scan_theme_files' => 1,
            'scan_emails' => 1,
            'scan_phone_numbers' => 1,
            'scan_api_keys' => 1,
            'scan_credit_cards' => 1,
            'scan_ssn' => 1,
            'scan_passwords' => 1,
            'scan_jwt_tokens' => 1,
            'scan_ip_addresses' => 0,
            'scheduled_scan' => 0,
            'scan_frequency' => 'daily',
            'email_notifications' => 1,
            'retention_days' => 30,
            'exclude_patterns' => ''
        );
    }
}