<?php
/**
 * Scanner functionality for Sensitive Data Scanner
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class Sensitive_Data_Scanner_Cognito_Scanner {
    
    /**
     * Patterns for different types of sensitive data
     */
    private $patterns = array();
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->sensitive_data_scanner_cognito_init_patterns();
        add_action('sensitive_data_scanner_cognito_scheduled_scan', array($this, 'sensitive_data_scanner_cognito_run_scheduled_scan'));
    }
    
    /**
     * Initialize regex patterns for different data types
     */
    private function sensitive_data_scanner_cognito_init_patterns() {
        $this->patterns = array(
            'email' => array(
                'pattern' => '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/',
                'risk_level' => 'Medium'
            ),
            'phone' => array(
                'pattern' => '/(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})/',
                'risk_level' => 'Low'
            ),
            'api_key' => array(
                'pattern' => '/(?i)(api[_-]?key|access[_-]?token|secret[_-]?key|private[_-]?key)[\s]*[=:]["\']*([a-zA-Z0-9_\-]{20,})/',
                'risk_level' => 'High'
            ),
            'credit_card' => array(
                'pattern' => '/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/',
                'risk_level' => 'High'
            ),
            'ssn' => array(
                'pattern' => '/\b\d{3}-?\d{2}-?\d{4}\b/',
                'risk_level' => 'High'
            ),
            'aws_key' => array(
                'pattern' => '/AKIA[0-9A-Z]{16}/',
                'risk_level' => 'High'
            ),
            'google_api' => array(
                'pattern' => '/AIza[0-9A-Za-z\-_]{35}/',
                'risk_level' => 'High'
            ),
            'stripe_key' => array(
                'pattern' => '/(sk|pk)_(test|live)_[0-9a-zA-Z]{24}/',
                'risk_level' => 'High'
            ),
            'github_token' => array(
                'pattern' => '/gh[pousr]_[A-Za-z0-9_]{36}/',
                'risk_level' => 'High'
            ),
            'jwt_token' => array(
                'pattern' => '/eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/',
                'risk_level' => 'Medium'
            ),
            'password' => array(
                'pattern' => '/(?i)(password|passwd|pwd)[\s]*[=:]["\']*([^\s"\']{8,})/',
                'risk_level' => 'High'
            ),
            'ip_address' => array(
                'pattern' => '/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/',
                'risk_level' => 'Low'
            )
        );
    }
    
    /**
     * Run full scan
     */
    public function sensitive_data_scanner_cognito_run_full_scan() {
        $settings = get_option('sensitive_data_scanner_cognito_settings', array());
        $results = array();
        
        // Clear previous results
        $database = new Sensitive_Data_Scanner_Cognito_Database();
        $database->sensitive_data_scanner_cognito_clear_scan_results();
        
        // Scan posts
        if (!empty($settings['scan_posts'])) {
            $results = array_merge($results, $this->sensitive_data_scanner_cognito_scan_posts());
        }
        
        // Scan pages
        if (!empty($settings['scan_pages'])) {
            $results = array_merge($results, $this->sensitive_data_scanner_cognito_scan_pages());
        }
        
        // Scan theme files
        if (!empty($settings['scan_theme_files'])) {
            $results = array_merge($results, $this->sensitive_data_scanner_cognito_scan_theme_files());
        }
        
        // Save results to database
        foreach ($results as $result) {
            $database->sensitive_data_scanner_cognito_save_scan_result($result);
        }
        
        return $results;
    }
    
    /**
     * Scan posts for sensitive data
     */
    private function sensitive_data_scanner_cognito_scan_posts() {
        $results = array();
        $posts = get_posts(array(
            'post_type' => 'post',
            'post_status' => 'publish',
            'numberposts' => -1
        ));
        
        foreach ($posts as $post) {
            $content = $post->post_content . ' ' . $post->post_title . ' ' . $post->post_excerpt;
            $found_data = $this->sensitive_data_scanner_cognito_scan_content($content);
            
            foreach ($found_data as $data) {
                $results[] = array(
                    'location_type' => 'Post',
                    'location_name' => $post->post_title,
                    'location_id' => $post->ID,
                    'data_type' => $data['type'],
                    'data_found' => $data['data'],
                    'risk_level' => $data['risk_level'],
                    'context' => $this->sensitive_data_scanner_cognito_get_context($content, $data['data'])
                );
            }
        }
        
        return $results;
    }
    
    /**
     * Scan pages for sensitive data
     */
    private function sensitive_data_scanner_cognito_scan_pages() {
        $results = array();
        $pages = get_posts(array(
            'post_type' => 'page',
            'post_status' => 'publish',
            'numberposts' => -1
        ));
        
        foreach ($pages as $page) {
            $content = $page->post_content . ' ' . $page->post_title . ' ' . $page->post_excerpt;
            $found_data = $this->sensitive_data_scanner_cognito_scan_content($content);
            
            foreach ($found_data as $data) {
                $results[] = array(
                    'location_type' => 'Page',
                    'location_name' => $page->post_title,
                    'location_id' => $page->ID,
                    'data_type' => $data['type'],
                    'data_found' => $data['data'],
                    'risk_level' => $data['risk_level'],
                    'context' => $this->sensitive_data_scanner_cognito_get_context($content, $data['data'])
                );
            }
        }
        
        return $results;
    }
    
    /**
     * Scan theme files for sensitive data
     */
    private function sensitive_data_scanner_cognito_scan_theme_files() {
        $results = array();
        $theme_root = get_theme_root();
        $active_theme = get_stylesheet();
        $theme_path = $theme_root . '/' . $active_theme;
        
        if (is_dir($theme_path)) {
            $files = $this->sensitive_data_scanner_cognito_get_php_files($theme_path);
            
            foreach ($files as $file) {
                if (is_readable($file)) {
                    $content = file_get_contents($file);
                    if ($content !== false) {
                        $found_data = $this->sensitive_data_scanner_cognito_scan_content($content);
                        
                        foreach ($found_data as $data) {
                            $results[] = array(
                                'location_type' => 'Theme File',
                                'location_name' => str_replace($theme_path . '/', '', $file),
                                'location_id' => null,
                                'data_type' => $data['type'],
                                'data_found' => $data['data'],
                                'risk_level' => $data['risk_level'],
                                'context' => $this->sensitive_data_scanner_cognito_get_context($content, $data['data'])
                            );
                        }
                    }
                }
            }
        }
        
        return $results;
    }
    
    /**
     * Get PHP files recursively from directory
     */
    private function sensitive_data_scanner_cognito_get_php_files($dir) {
        $files = array();
        
        if (!is_dir($dir)) {
            return $files;
        }
        
        try {
            $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
            
            foreach ($iterator as $file) {
                if ($file->isFile() && in_array($file->getExtension(), array('php', 'js', 'css'))) {
                    $files[] = $file->getPathname();
                }
            }
        } catch (Exception $e) {
            // Handle directory access errors
            if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
				echo('Sensitive Data Scanner: Error accessing directory ' . wp_kses_post($dir) . ': ' . wp_kses_post($e->getMessage()));
			}
        }
        
        return $files;
    }
    
    /**
     * Scan content for sensitive data
     */
    private function sensitive_data_scanner_cognito_scan_content($content) {
        $found_data = array();
        $settings = get_option('sensitive_data_scanner_cognito_settings', array());
        
        foreach ($this->patterns as $type => $pattern_data) {
            // Check if this type is enabled in settings
            $setting_key = 'scan_' . str_replace('_', '_', $type);
            if (isset($settings[$setting_key]) && !$settings[$setting_key]) {
                continue;
            }
            
            preg_match_all($pattern_data['pattern'], $content, $matches);
            
            if (!empty($matches[0])) {
                foreach ($matches[0] as $match) {
                    // Skip common false positives
                    if ($this->sensitive_data_scanner_cognito_is_false_positive($match, $type)) {
                        continue;
                    }
                    
                    $found_data[] = array(
                        'type' => ucfirst(str_replace('_', ' ', $type)),
                        'data' => $match,
                        'risk_level' => $pattern_data['risk_level']
                    );
                }
            }
        }
        
        return $found_data;
    }
    
    /**
     * Check if match is a false positive
     */
    private function sensitive_data_scanner_cognito_is_false_positive($match, $type) {
        $false_positives = array(
            'email' => array(
                'example@example.com',
                'test@test.com',
                'admin@admin.com',
                'user@domain.com',
                'noreply@wordpress.org'
            ),
            'phone' => array(
                '123-456-7890',
                '(123) 456-7890',
                '555-555-5555'
            ),
            'credit_card' => array(
                '4111111111111111', // Test card numbers
                '4000000000000002',
                '5555555555554444'
            ),
            'ip_address' => array(
                '127.0.0.1',
                '0.0.0.0',
                '255.255.255.255',
                '192.168.1.1'
            )
        );
        
        if (isset($false_positives[$type])) {
            return in_array($match, $false_positives[$type]);
        }
        
        return false;
    }
    
    /**
     * Get context around found data
     */
    private function sensitive_data_scanner_cognito_get_context($content, $data) {
        $pos = strpos($content, $data);
        if ($pos === false) {
            return '';
        }
        
        $start = max(0, $pos - 50);
        $length = min(100, strlen($content) - $start);
        $context = substr($content, $start, $length);
        
        // Clean up context
        $context = wp_strip_all_tags($context);
        $context = preg_replace('/\s+/', ' ', $context);
        
        return trim($context);
    }
    
    /**
     * Run scheduled scan
     */
    public function sensitive_data_scanner_cognito_run_scheduled_scan() {
        $this->sensitive_data_scanner_cognito_run_full_scan();
        
        // Send notification if high-risk items found
        $database = new Sensitive_Data_Scanner_Cognito_Database();
        $results = $database->sensitive_data_scanner_cognito_get_scan_results();
        
        $high_risk_count = 0;
        foreach ($results as $result) {
            if ($result->risk_level === 'High') {
                $high_risk_count++;
            }
        }
        
        if ($high_risk_count > 0) {
            $this->sensitive_data_scanner_cognito_send_notification($high_risk_count);
        }
    }
    
    /**
     * Send notification email
     */
    private function sensitive_data_scanner_cognito_send_notification($high_risk_count) {
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        
        $subject = sprintf(
            /* translators: %s: site name */
            esc_html__('[%s] Sensitive Data Scanner Alert', 'sensitive-data-scanner-cognito'),
            $site_name
        );
        
        $message = sprintf(
            /* translators: %1$d: number of high-risk issues, %2$s: site URL */
            esc_html__('The Sensitive Data Scanner found %1$d high-risk issues on your website %2$s. Please review these issues as soon as possible.', 'sensitive-data-scanner-cognito'),
            $high_risk_count,
            home_url()
        );
        
        $message .= "\n\n" . esc_html__('You can view the full report at:', 'sensitive-data-scanner-cognito');
        $message .= "\n" . admin_url('admin.php?page=sensitive-data-scanner-cognito');
        
        wp_mail($admin_email, $subject, $message);
    }
    
    /**
     * Schedule regular scans
     */
    public function sensitive_data_scanner_cognito_schedule_scan($frequency = 'daily') {
        // Clear existing schedule
        wp_clear_scheduled_hook('sensitive_data_scanner_cognito_scheduled_scan');
        
        // Schedule new scan
        if (!wp_next_scheduled('sensitive_data_scanner_cognito_scheduled_scan')) {
            wp_schedule_event(time(), $frequency, 'sensitive_data_scanner_cognito_scheduled_scan');
        }
    }
    
    /**
     * Unschedule scans
     */
    public function sensitive_data_scanner_cognito_unschedule_scan() {
        wp_clear_scheduled_hook('sensitive_data_scanner_cognito_scheduled_scan');
    }
}