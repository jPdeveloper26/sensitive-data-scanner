/**
 * Sensitive Data Scanner Admin JavaScript
 */

(function($) {
    'use strict';
    
    var SensitiveDataScannerAdmin = {
        
        /**
         * Initialize admin functionality
         */
        init: function() {
            console.log('SensitiveDataScannerAdmin.init() called');
            
            // Check if required objects exist
            if (typeof sensitiveDataScannerCognito === 'undefined') {
                console.error('Sensitive Data Scanner: Required JavaScript object not found');
                return;
            }
            
            console.log('sensitiveDataScannerCognito object found:', sensitiveDataScannerCognito);
            
            this.bindEvents();
            this.initProgressIndicators();
            
            // Debug info
            console.log('Sensitive Data Scanner Admin initialized successfully');
        },
        
        /**
         * Bind event handlers
         */
        bindEvents: function() {
            var self = this; // Store reference to this
            console.log('Binding events...');
            
            // Store original button text
            $('#run-scan-btn').each(function() {
                $(this).data('original-text', $(this).text());
            });
            
            // AJAX scan button
            $('#run-scan-btn').on('click', function(e) {
                console.log('Scan button clicked');
                self.runAjaxScan(e);
            });
            
            // Settings form changes
            $('input[name*="scheduled_scan"]').on('change', function() {
                self.toggleScheduleSettings.call(this);
            });
            
            // Form validation - only for WordPress settings forms (options.php)
            $('form[action="options.php"]').on('submit', function(e) {
                console.log('Settings form submitted, validating...');
                return self.validateForm(e);
            });
            
            // Exclude action forms from validation
            $('form[method="post"]:not([action="options.php"])').on('submit', function(e) {
                console.log('Action form submitted (no validation needed)');
                // Let these forms submit without validation
                return true;
            });
            
            // Auto-save settings (debounced)
            var autoSaveTimeout;
            $('.sensitive-data-scanner-cognito-settings input, .sensitive-data-scanner-cognito-settings select').on('change', function() {
                clearTimeout(autoSaveTimeout);
                autoSaveTimeout = setTimeout(function() {
                    self.showAutoSaveIndicator();
                }, 1000);
            });
            
            console.log('Events bound successfully');
        },
        
        /**
         * Initialize progress indicators
         */
        initProgressIndicators: function() {
            // Check if there's a scan in progress
            this.checkScanStatus();
        },
        
        /**
         * Run AJAX scan
         */
        runAjaxScan: function(e) {
            e.preventDefault();
            
            var $button = $(e.target);
            var $progress = $('#scan-progress');
            var $status = $('#scan-status');
            
            // Store original text if not already stored
            if (!$button.data('original-text')) {
                $button.data('original-text', $button.text());
            }
            
            // Disable button and show loading state
            $button.prop('disabled', true).addClass('loading');
            $button.text(sensitiveDataScannerCognito.strings.scanning);
            
            // Show progress bar
            $progress.show();
            $status.text(sensitiveDataScannerCognito.strings.scanning);
            
            // Start progress animation
            this.animateProgress();
            
            // Make AJAX request
            $.ajax({
                url: sensitiveDataScannerCognito.ajax_url,
                type: 'POST',
                data: {
                    action: 'sensitive_data_scanner_cognito_run_scan',
                    nonce: sensitiveDataScannerCognito.nonce
                },
                timeout: 300000, // 5 minutes timeout for long scans
                beforeSend: function() {
                    console.log('Starting AJAX scan request');
                },
                success: this.handleScanSuccess.bind(this),
                error: this.handleScanError.bind(this),
                complete: function() {
                    console.log('AJAX scan request completed');
                    // Re-enable button
                    $button.prop('disabled', false).removeClass('loading');
                    $button.text($button.data('original-text') || 'Start Scan');
                }
            });
        },
        
        /**
         * Handle successful scan
         */
        handleScanSuccess: function(response) {
            var $progress = $('#scan-progress');
            var $status = $('#scan-status');
            var $progressFill = $('.progress-fill');
            
            if (response.success) {
                // Complete progress bar
                $progressFill.css('width', '100%');
                $status.text(sensitiveDataScannerCognito.strings.scan_complete);
                
                // Build success message
                var message = response.data.message;
                if (response.data.results_count !== undefined) {
                    if (response.data.results_count === 0) {
                        message += ' No sensitive data found.';
                    } else {
                        message += ' Found ' + response.data.results_count + ' total issues';
                        if (response.data.high_risk_count && response.data.high_risk_count > 0) {
                            message += ' (' + response.data.high_risk_count + ' high-risk)';
                        }
                        message += '.';
                    }
                }
                
                // Show success message
                this.showNotice('success', message);
                
                // Hide progress after delay and reload
                setTimeout(function() {
                    $progress.fadeOut();
                    // Reload page to show new results
                    window.location.reload();
                }, 2000);
            } else {
                this.handleScanError(response);
            }
        },
        
        /**
         * Handle scan error
         */
        handleScanError: function(response) {
            console.error('Scan error:', response);
            
            var $progress = $('#scan-progress');
            var $status = $('#scan-status');
            
            $status.text(sensitiveDataScannerCognito.strings.scan_error);
            $progress.addClass('error');
            
            var message = response.responseJSON && response.responseJSON.data && response.responseJSON.data.message ? 
                         response.responseJSON.data.message : 
                         sensitiveDataScannerCognito.strings.scan_error;
            
            this.showNotice('error', message);
            
            // Hide progress after delay
            setTimeout(function() {
                $progress.fadeOut().removeClass('error');
            }, 5000);
        },
        
        /**
         * Animate progress bar
         */
        animateProgress: function() {
            var $progressFill = $('.progress-fill');
            var progress = 0;
            
            var interval = setInterval(function() {
                progress += Math.random() * 10;
                if (progress > 85) {
                    progress = 85; // Don't complete until we get the response
                    clearInterval(interval);
                }
                $progressFill.css('width', progress + '%');
            }, 800);
            
            // Store interval ID so we can clear it if needed
            $progressFill.data('progress-interval', interval);
        },
        
        /**
         * Toggle schedule settings visibility
         */
        toggleScheduleSettings: function() {
            var $scheduleOptions = $('.schedule-options');
            var isChecked = $(this).is(':checked');
            
            if (isChecked) {
                $scheduleOptions.slideDown();
            } else {
                $scheduleOptions.slideUp();
            }
        },
        
        /**
         * Validate form before submission
         */
        validateForm: function(e) {
            var $form = $(e.target);
            
            // Only validate WordPress settings forms (options.php)
            if ($form.attr('action') !== 'options.php') {
                console.log('Skipping validation for non-settings form');
                return true;
            }
            
            console.log('Validating settings form...');
            
            var isValid = true;
            var errors = [];
            var self = this;
            
            // Check if at least one scan option is selected
            var scanOptions = $form.find('input[name*="scan_posts"], input[name*="scan_pages"], input[name*="scan_theme_files"]');
            if (scanOptions.length > 0 && scanOptions.filter(':checked').length === 0) {
                errors.push('Please select at least one content type to scan.');
                isValid = false;
            }
            
            // Check if at least one data type is selected
            var dataTypes = $form.find('input[name*="scan_emails"], input[name*="scan_phone"], input[name*="scan_api"]');
            if (dataTypes.length > 0 && dataTypes.filter(':checked').length === 0) {
                errors.push('Please select at least one data type to scan for.');
                isValid = false;
            }
            
            // Validate retention days
            var retentionDays = $form.find('input[name*="retention_days"]').val();
            if (retentionDays && (retentionDays < 1 || retentionDays > 365)) {
                errors.push('Retention days must be between 1 and 365.');
                isValid = false;
            }
            
            if (!isValid) {
                e.preventDefault();
                console.log('Form validation failed:', errors);
                self.showNotice('error', errors.join('<br>'));
            } else {
                console.log('Form validation passed');
            }
            
            return isValid;
        },
        
        /**
         * Check scan status
         */
        checkScanStatus: function() {
            var self = this;
            // This could be used to check if a scan is running in the background
            // For now, we'll just check if there are recent results
            var lastScan = $('.last-scan').text();
            if (lastScan) {
                var lastScanTime = new Date(lastScan);
                var now = new Date();
                var diffMinutes = (now - lastScanTime) / (1000 * 60);
                
                if (diffMinutes < 5) {
                    self.showNotice('info', 'A scan was recently completed.');
                }
            }
        },
        
        /**
         * Show auto-save indicator
         */
        showAutoSaveIndicator: function() {
            var $indicator = $('<div class="auto-save-indicator">Auto-saving...</div>');
            $indicator.css({
                position: 'fixed',
                top: '32px',
                right: '20px',
                background: '#00a0d2',
                color: 'white',
                padding: '8px 15px',
                borderRadius: '3px',
                fontSize: '12px',
                zIndex: 100000
            });
            
            $('body').append($indicator);
            
            setTimeout(function() {
                $indicator.fadeOut(function() {
                    $(this).remove();
                });
            }, 2000);
        },
        
        /**
         * Show admin notice
         */
        showNotice: function(type, message) {
            // Remove any existing notices from this plugin
            $('.notice.sensitive-data-scanner-notice').remove();
            
            var $notice = $('<div class="notice notice-' + type + ' is-dismissible sensitive-data-scanner-notice"><p>' + message + '</p><button type="button" class="notice-dismiss"><span class="screen-reader-text">Dismiss this notice.</span></button></div>');
            
            // Insert after the h1 or at the top of wrap
            var $target = $('.wrap h1');
            if ($target.length) {
                $target.after($notice);
            } else {
                $('.wrap').prepend($notice);
            }
            
            // Auto-dismiss after 5 seconds
            setTimeout(function() {
                $notice.fadeOut(function() {
                    $(this).remove();
                });
            }, 5000);
            
            // Add dismiss functionality
            $notice.on('click', '.notice-dismiss', function(e) {
                e.preventDefault();
                $notice.fadeOut(function() {
                    $(this).remove();
                });
            });
            
            // Scroll to notice
            $('html, body').animate({
                scrollTop: $notice.offset().top - 50
            }, 300);
        },
        
        /**
         * Export results
         */
        exportResults: function(format) {
            format = format || 'csv';
            
            var form = $('<form>', {
                method: 'POST',
                action: window.location.href
            });
            
            form.append($('<input>', {
                type: 'hidden',
                name: 'action',
                value: 'export_results'
            }));
            
            form.append($('<input>', {
                type: 'hidden',
                name: 'format',
                value: format
            }));
            
            form.append($('<input>', {
                type: 'hidden',
                name: 'sensitive_data_scanner_cognito_settings_nonce',
                value: sensitiveDataScannerCognito.nonce
            }));
            
            $('body').append(form);
            form.submit();
            form.remove();
        },
        
        /**
         * Filter results table
         */
        filterResults: function(filters) {
            var $table = $('.wp-list-table tbody tr');
            
            $table.show(); // Show all rows first
            
            if (filters.risk_level) {
                $table.filter(function() {
                    return $(this).find('.risk-level').text().toLowerCase() !== filters.risk_level.toLowerCase();
                }).hide();
            }
            
            if (filters.data_type) {
                $table.filter(function() {
                    return $(this).find('.data-type-badge').text().toLowerCase() !== filters.data_type.toLowerCase();
                }).hide();
            }
            
            if (filters.location_type) {
                $table.filter(function() {
                    return $(this).find('td:first').text().toLowerCase().indexOf(filters.location_type.toLowerCase()) === -1;
                }).hide();
            }
        },
        
        /**
         * Initialize tooltips
         */
        initTooltips: function() {
            $('[data-tooltip]').each(function() {
                var $element = $(this);
                var tooltipText = $element.data('tooltip');
                
                $element.on('mouseenter', function() {
                    var $tooltip = $('<div class="scanner-tooltip">' + tooltipText + '</div>');
                    $tooltip.css({
                        position: 'absolute',
                        background: '#1d2327',
                        color: 'white',
                        padding: '5px 10px',
                        borderRadius: '3px',
                        fontSize: '12px',
                        zIndex: 100000,
                        whiteSpace: 'nowrap'
                    });
                    
                    $('body').append($tooltip);
                    
                    var offset = $element.offset();
                    $tooltip.css({
                        top: offset.top - $tooltip.outerHeight() - 5,
                        left: offset.left + ($element.outerWidth() / 2) - ($tooltip.outerWidth() / 2)
                    });
                });
                
                $element.on('mouseleave', function() {
                    $('.scanner-tooltip').remove();
                });
            });
        },
        
        /**
         * Handle keyboard shortcuts
         */
        handleKeyboardShortcuts: function(e) {
            // Ctrl/Cmd + S to save settings
            if ((e.ctrlKey || e.metaKey) && e.which === 83) {
                e.preventDefault();
                $('form input[type="submit"]').click();
            }
            
            // Ctrl/Cmd + R to run scan
            if ((e.ctrlKey || e.metaKey) && e.which === 82) {
                e.preventDefault();
                $('#run-scan-btn').click();
            }
        }
    };

    // Initialize when document is ready
    $(document).ready(function() {
        SensitiveDataScannerAdmin.init();
        
        // Initialize tooltips
        SensitiveDataScannerAdmin.initTooltips();
        
        // Handle responsive table behavior
        function handleResize() {
            var $table = $('.wp-list-table');
            if ($(window).width() < 768) {
                $table.addClass('mobile-responsive');
            } else {
                $table.removeClass('mobile-responsive');
            }
        }
        
        $(window).on('resize', handleResize);
        handleResize(); // Run on load
    });

    // Initialize keyboard shortcuts
    $(document).on('keydown', function(e) {
        SensitiveDataScannerAdmin.handleKeyboardShortcuts.call(SensitiveDataScannerAdmin, e);
    });

})(jQuery);