<?php
/**
 * Database functionality for Sensitive Data Scanner
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class Sensitive_Data_Scanner_Cognito_Database {
    
    /**
     * Table name for scan results
     */
    private $table_name;
    
    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'sensitive_data_scanner_cognito_results';
    }
    
    /**
     * Create database tables
     */
    public function sensitive_data_scanner_cognito_create_tables() {
        global $wpdb;
        
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE {$this->table_name} (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            location_type varchar(50) NOT NULL,
            location_name varchar(255) NOT NULL,
            location_id bigint(20) NULL,
            data_type varchar(50) NOT NULL,
            data_found text NOT NULL,
            risk_level varchar(20) NOT NULL,
            context text,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY location_type (location_type),
            KEY risk_level (risk_level),
            KEY created_at (created_at)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
        
        // Update database version
        add_option('sensitive_data_scanner_cognito_db_version', '1.0');
    }
    
    /**
     * Save scan result to database
     */
    public function sensitive_data_scanner_cognito_save_scan_result($result) {
        global $wpdb;
        
        $inserted = $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            $this->table_name,
            array(
                'location_type' => sanitize_text_field($result['location_type']),
                'location_name' => sanitize_text_field($result['location_name']),
                'location_id' => !empty($result['location_id']) ? intval($result['location_id']) : null,
                'data_type' => sanitize_text_field($result['data_type']),
                'data_found' => sanitize_textarea_field($result['data_found']),
                'risk_level' => sanitize_text_field($result['risk_level']),
                'context' => sanitize_textarea_field($result['context']),
                'created_at' => current_time('mysql', true)
            ),
            array(
                '%s', // location_type
                '%s', // location_name
                '%d', // location_id
                '%s', // data_type
                '%s', // data_found
                '%s', // risk_level
                '%s', // context
                '%s'  // created_at
            )
        );
        
        // Clear cache when new data is added
        if ($inserted) {
            $this->sensitive_data_scanner_cognito_clear_cache();
        }
        
        return $inserted;
    }
    
    /**
     * Get scan results from database
     */
    public function sensitive_data_scanner_cognito_get_scan_results($limit = null, $offset = 0, $filters = array()) {
        global $wpdb;
        
        // Create cache key based on parameters
        $cache_key = 'sds_results_' . md5(serialize(array($limit, $offset, $filters)));
        $cached_results = wp_cache_get($cache_key, 'sensitive_data_scanner');
        
        if (false !== $cached_results) {
            return $cached_results;
        }
        
        $where_conditions = array('1=1');
        $where_values = array();
        
        // Apply filters
        if (!empty($filters['risk_level'])) {
            $where_conditions[] = 'risk_level = %s';
            $where_values[] = sanitize_text_field($filters['risk_level']);
        }
        
        if (!empty($filters['data_type'])) {
            $where_conditions[] = 'data_type = %s';
            $where_values[] = sanitize_text_field($filters['data_type']);
        }
        
        if (!empty($filters['location_type'])) {
            $where_conditions[] = 'location_type = %s';
            $where_values[] = sanitize_text_field($filters['location_type']);
        }
        
        if (!empty($filters['date_from'])) {
            $where_conditions[] = 'created_at >= %s';
            $where_values[] = sanitize_text_field($filters['date_from']);
        }
        
        if (!empty($filters['date_to'])) {
            $where_conditions[] = 'created_at <= %s';
            $where_values[] = sanitize_text_field($filters['date_to']);
        }
        
        $where_clause = implode(' AND ', $where_conditions);
        
        // Build query with escaped table name
        $query = sprintf(
            'SELECT * FROM %s WHERE %s ORDER BY created_at DESC',
            $wpdb->_escape($this->table_name),
            $where_clause
        );
        
        if ($limit) {
            $query .= ' LIMIT %d';
            $where_values[] = intval($limit);
            
            if ($offset) {
                $query .= ' OFFSET %d';
                $where_values[] = intval($offset);
            }
        }
        
        if (!empty($where_values)) {
            $results = $wpdb->get_results($wpdb->prepare($query, $where_values)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        } else {
            $results = $wpdb->get_results($query); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        }
        
        // Cache results for 5 minutes
        wp_cache_set($cache_key, $results, 'sensitive_data_scanner', 300);
        
        return $results;
    }
    
    /**
     * Get scan result by ID
     */
    public function sensitive_data_scanner_cognito_get_scan_result($id) {
        global $wpdb;
        
        $query = sprintf(
            'SELECT * FROM %s WHERE id = %%d',
            $wpdb->_escape($this->table_name)
        );
        
        return $wpdb->get_row($wpdb->prepare($query, intval($id))); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
    }
    
    /**
     * Delete scan result
     */
    public function sensitive_data_scanner_cognito_delete_scan_result($id) {
        global $wpdb;
        
        $result = $wpdb->delete( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
            $this->table_name,
            array('id' => intval($id)),
            array('%d')
        );
        
        // Clear cache when data is deleted
        if ($result) {
            $this->sensitive_data_scanner_cognito_clear_cache();
        }
        
        return $result;
    }
    
    /**
     * Clear all scan results
     */
    public function sensitive_data_scanner_cognito_clear_scan_results() {
        global $wpdb;
        
        $query = sprintf(
            'TRUNCATE TABLE %s',
            $wpdb->_escape($this->table_name)
        );
        
        $result = $wpdb->query($query); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        
        // Clear cache when data is cleared
        if ($result) {
            $this->sensitive_data_scanner_cognito_clear_cache();
        }
        
        return $result;
    }
    
    /**
     * Get scan statistics
     */
    public function sensitive_data_scanner_cognito_get_statistics() {
        global $wpdb;
        
        // Check cache first
        $cache_key = 'sds_statistics';
        $cached_stats = wp_cache_get($cache_key, 'sensitive_data_scanner');
        
        if (false !== $cached_stats) {
            return $cached_stats;
        }
        
        $stats = array();
        $table_name = $wpdb->_escape($this->table_name);
        
        // Total results
        $stats['total'] = $wpdb->get_var(sprintf('SELECT COUNT(*) FROM %s', $table_name)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        
        // Results by risk level
        $risk_levels = $wpdb->get_results(sprintf( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            'SELECT risk_level, COUNT(*) as count FROM %s GROUP BY risk_level',
            $table_name
        ));
        
        foreach ($risk_levels as $level) {
            $stats['by_risk_level'][strtolower($level->risk_level)] = $level->count;
        }
        
        // Results by data type
        $data_types = $wpdb->get_results(sprintf( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            'SELECT data_type, COUNT(*) as count FROM %s GROUP BY data_type ORDER BY count DESC',
            $table_name
        ));
        
        foreach ($data_types as $type) {
            $stats['by_data_type'][$type->data_type] = $type->count;
        }
        
        // Results by location type
        $location_types = $wpdb->get_results(sprintf( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            'SELECT location_type, COUNT(*) as count FROM %s GROUP BY location_type',
            $table_name
        ));
        
        foreach ($location_types as $type) {
            $stats['by_location_type'][$type->location_type] = $type->count;
        }
        
        // Recent activity (last 7 days)
        $recent = $wpdb->get_results(sprintf( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            'SELECT DATE(created_at) as date, COUNT(*) as count 
             FROM %s 
             WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) 
             GROUP BY DATE(created_at) 
             ORDER BY date DESC',
            $table_name
        ));
        
        foreach ($recent as $day) {
            $stats['recent_activity'][$day->date] = $day->count;
        }
        
        // Last scan date
        $stats['last_scan'] = $wpdb->get_var(sprintf( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
            'SELECT MAX(created_at) FROM %s',
            $table_name
        ));
        
        // Cache for 10 minutes
        wp_cache_set($cache_key, $stats, 'sensitive_data_scanner', 600);
        
        return $stats;
    }
    
    /**
     * Get duplicate results
     */
    public function sensitive_data_scanner_cognito_get_duplicates() {
        global $wpdb;
        
        $query = sprintf(
            'SELECT data_found, data_type, COUNT(*) as count 
             FROM %s 
             GROUP BY data_found, data_type 
             HAVING count > 1 
             ORDER BY count DESC',
            $wpdb->_escape($this->table_name)
        );
        
        return $wpdb->get_results($query); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
    }
    
    /**
     * Remove duplicate results (keep most recent)
     */
    public function sensitive_data_scanner_cognito_remove_duplicates() {
        global $wpdb;
        
        $table_name = $wpdb->_escape($this->table_name);
        $query = sprintf(
            'DELETE t1 FROM %1$s t1
             INNER JOIN %1$s t2 
             WHERE t1.id < t2.id 
             AND t1.data_found = t2.data_found 
             AND t1.data_type = t2.data_type 
             AND t1.location_type = t2.location_type 
             AND t1.location_name = t2.location_name',
            $table_name
        );
        
        $result = $wpdb->query($query); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        
        // Clear cache when data is modified
        if ($result) {
            $this->sensitive_data_scanner_cognito_clear_cache();
        }
        
        return $result;
    }
    
    /**
     * Export scan results to CSV
     */
    public function sensitive_data_scanner_cognito_export_to_csv($filters = array()) {
        $results = $this->sensitive_data_scanner_cognito_get_scan_results(null, 0, $filters);
        
        if (empty($results)) {
            return false;
        }
        
        $filename = 'sensitive-data-scan-' . gmdate('Y-m-d-H-i-s') . '.csv';
        $upload_dir = wp_upload_dir();
        $file_path = $upload_dir['path'] . '/' . $filename;
        
        // Use WordPress filesystem instead of direct PHP functions
        global $wp_filesystem;
        if (empty($wp_filesystem)) {
            require_once ABSPATH . '/wp-admin/includes/file.php';
            WP_Filesystem();
        }
        
        // Create CSV content
        $csv_content = '';
        
        // Add CSV headers
        $headers = array(
            'Location Type',
            'Location Name',
            'Location ID',
            'Data Type',
            'Data Found',
            'Risk Level',
            'Context',
            'Date Found'
        );
        $csv_content .= '"' . implode('","', $headers) . '"' . "\n";
        
        // Add data rows
        foreach ($results as $result) {
            $row = array(
                $result->location_type,
                $result->location_name,
                $result->location_id,
                $result->data_type,
                $result->data_found,
                $result->risk_level,
                $result->context,
                $result->created_at
            );
            
            // Escape and quote each field
            $escaped_row = array_map(function($field) {
                return '"' . str_replace('"', '""', $field) . '"';
            }, $row);
            
            $csv_content .= implode(',', $escaped_row) . "\n";
        }
        
        // Write file using WordPress filesystem
        if ($wp_filesystem->put_contents($file_path, $csv_content, FS_CHMOD_FILE)) {
            return array(
                'file_path' => $file_path,
                'file_url' => $upload_dir['url'] . '/' . $filename,
                'filename' => $filename
            );
        }
        
        return false;
    }
    
    /**
     * Clean up old results
     */
    public function sensitive_data_scanner_cognito_cleanup_old_results($days = 30) {
        global $wpdb;
        
        $query = sprintf(
            'DELETE FROM %s WHERE created_at < DATE_SUB(NOW(), INTERVAL %%d DAY)',
            $wpdb->_escape($this->table_name)
        );
        
        $result = $wpdb->query($wpdb->prepare($query, intval($days))); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        
        // Clear cache when data is cleaned up
        if ($result) {
            $this->sensitive_data_scanner_cognito_clear_cache();
        }
        
        return $result;
    }
    
    /**
     * Check if table exists
     */
    public function sensitive_data_scanner_cognito_table_exists() {
        global $wpdb;
        
        $query = 'SHOW TABLES LIKE %s';
        $result = $wpdb->get_var($wpdb->prepare($query, $this->table_name)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        
        return $result === $this->table_name;
    }
    
    /**
     * Drop database tables (for uninstall)
     */
    public function sensitive_data_scanner_cognito_drop_tables() {
        global $wpdb;
        
        $query = sprintf(
            'DROP TABLE IF EXISTS %s',
            $wpdb->_escape($this->table_name)
        );
        
        $wpdb->query($query); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
        delete_option('sensitive_data_scanner_cognito_db_version');
        
        // Clear all cache
        $this->sensitive_data_scanner_cognito_clear_cache();
    }
    
    /**
     * Clear plugin cache
     */
    private function sensitive_data_scanner_cognito_clear_cache() {
        wp_cache_flush_group('sensitive_data_scanner');
    }
}