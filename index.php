<?php


class wp_data_validation
{

	function _wp_call_all_hook($args) {
	    global $wp_filter;

	    reset( $wp_filter['all'] );
	    do {
	        foreach ( (array) current($wp_filter['all']) as $the_ )
	            if ( !is_null($the_['function']) )
	                call_user_func_array($the_['function'], $args);

	    } while ( next($wp_filter['all']) !== false );
	}

	function apply_filters( $tag, $value ) {
	    global $wp_filter, $merged_filters, $wp_current_filter;

	    $args = array();

	    // Do 'all' actions first.
	    if ( isset($wp_filter['all']) ) {
	        $wp_current_filter[] = $tag;
	        $args = func_get_args();
	        $this->_wp_call_all_hook($args);
	    }

	    if ( !isset($wp_filter[$tag]) ) {
	        if ( isset($wp_filter['all']) )
	            array_pop($wp_current_filter);
	        return $value;
	    }

	    if ( !isset($wp_filter['all']) )
	        $wp_current_filter[] = $tag;

	    // Sort.
	    if ( !isset( $merged_filters[ $tag ] ) ) {
	        ksort($wp_filter[$tag]);
	        $merged_filters[ $tag ] = true;
	    }

	    reset( $wp_filter[ $tag ] );

	    if ( empty($args) )
	        $args = func_get_args();

	    do {
	        foreach ( (array) current($wp_filter[$tag]) as $the_ )
	            if ( !is_null($the_['function']) ){
	                $args[1] = $value;
	                $value = call_user_func_array($the_['function'], array_slice($args, 1, (int) $the_['accepted_args']));
	            }

	    } while ( next($wp_filter[$tag]) !== false );

	    array_pop( $wp_current_filter );

	    return $value;
	}

	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************

	function wp_check_invalid_utf8( $string, $strip = false ) {
	    $string = (string) $string;

	    if ( 0 === strlen( $string ) ) {
	        return '';
	    }

	    // Store the site charset as a static to avoid multiple calls to get_option()
	    static $is_utf8 = null;
	    if ( ! isset( $is_utf8 ) ) {
	        $is_utf8 = in_array( 'UTF-8', array( 'utf8', 'utf-8', 'UTF8', 'UTF-8' ) );
	    }
	    if ( ! $is_utf8 ) {
	        return $string;
	    }

	    // Check for support for utf8 in the installed PCRE library once and store the result in a static
	    static $utf8_pcre = null;
	    if ( ! isset( $utf8_pcre ) ) {
	        $utf8_pcre = @preg_match( '/^./u', 'a' );
	    }
	    // We can't demand utf8 in the PCRE installation, so just return the string in those cases
	    if ( !$utf8_pcre ) {
	        return $string;
	    }

	    // preg_match fails when it encounters invalid UTF8 in $string
	    if ( 1 === @preg_match( '/^./us', $string ) ) {
	        return $string;
	    }

	    // Attempt to strip the bad chars if requested (not recommended)
	    if ( $strip && function_exists( 'iconv' ) ) {
	        return iconv( 'utf-8', 'utf-8', $string );
	    }

	    return '';
	}

	function wp_kses_post( $data ) {
	    return $this->wp_kses( $data, 'post' );
	}

	function wp_kses( $string, $allowed_html, $allowed_protocols = array() ) {
	    if ( empty( $allowed_protocols ) )
	        $allowed_protocols = $this->wp_allowed_protocols();
	    $string = $this->wp_kses_no_null( $string, array( 'slash_zero' => 'keep' ) );
	    $string = $this->wp_kses_js_entities($string);
	    $string = $this->wp_kses_normalize_entities($string);
	    $string = $this->wp_kses_hook($string, $allowed_html, $allowed_protocols); // WP changed the order of these funcs and added args to wp_kses_hook
	    return $this->wp_kses_split($string, $allowed_html, $allowed_protocols);
	}

	function wp_kses_split( $string, $allowed_html, $allowed_protocols ) {
	    global $pass_allowed_html, $pass_allowed_protocols;
	    $pass_allowed_html = $allowed_html;
	    $pass_allowed_protocols = $allowed_protocols;
	    return preg_replace_callback( '%(<!--.*?(-->|$))|(<[^>]*(>|$)|>)%', 'wp_data_validation::_wp_kses_split_callback', $string );
	}

	function _wp_kses_split_callback( $match ) {
	    global $pass_allowed_html, $pass_allowed_protocols;
	    return $this->wp_kses_split2( $match[0], $pass_allowed_html, $pass_allowed_protocols );
	}

	function wp_kses_split2($string, $allowed_html, $allowed_protocols) {
	    $string = $this->wp_kses_stripslashes($string);

	    if (substr($string, 0, 1) != '<')
	        return '&gt;';
	    // It matched a ">" character

	    if ( '<!--' == substr( $string, 0, 4 ) ) {
	        $string = str_replace( array('<!--', '-->'), '', $string );
	        while ( $string != ($newstring = wp_kses($string, $allowed_html, $allowed_protocols)) )
	            $string = $newstring;
	        if ( $string == '' )
	            return '';
	        // prevent multiple dashes in comments
	        $string = preg_replace('/--+/', '-', $string);
	        // prevent three dashes closing a comment
	        $string = preg_replace('/-$/', '', $string);
	        return "<!--{$string}-->";
	    }
	    // Allow HTML comments

	    if (!preg_match('%^<\s*(/\s*)?([a-zA-Z0-9]+)([^>]*)>?$%', $string, $matches))
	        return '';
	    // It's seriously malformed

	    $slash = trim($matches[1]);
	    $elem = $matches[2];
	    $attrlist = $matches[3];

	    if ( ! is_array( $allowed_html ) )
	        $allowed_html = $this->wp_kses_allowed_html( $allowed_html );

	    if ( ! isset($allowed_html[strtolower($elem)]) )
	        return '';
	    // They are using a not allowed HTML element

	    if ($slash != '')
	        return "</$elem>";
	    // No attributes are allowed for closing elements

	    return $this->wp_kses_attr( $elem, $attrlist, $allowed_html, $allowed_protocols );
	}

	function wp_kses_attr($element, $attr, $allowed_html, $allowed_protocols) {
	    if ( ! is_array( $allowed_html ) )
	        $allowed_html = $this->wp_kses_allowed_html( $allowed_html );

	    // Is there a closing XHTML slash at the end of the attributes?
	    $xhtml_slash = '';
	    if (preg_match('%\s*/\s*$%', $attr))
	        $xhtml_slash = ' /';

	    // Are any attributes allowed at all for this element?
	    if ( ! isset($allowed_html[strtolower($element)]) || count($allowed_html[strtolower($element)]) == 0 )
	        return "<$element$xhtml_slash>";

	    // Split it
	    $attrarr = $this->wp_kses_hair($attr, $allowed_protocols);

	    // Go through $attrarr, and save the allowed attributes for this element
	    // in $attr2
	    $attr2 = '';
	    foreach ( $attrarr as $arreach ) {
	        if ( $this->wp_kses_attr_check( $arreach['name'], $arreach['value'], $arreach['whole'], $arreach['vless'], $element, $allowed_html ) ) {
	            $attr2 .= ' '.$arreach['whole'];
	        }
	    }

	    // Remove any "<" or ">" characters
	    $attr2 = preg_replace('/[<>]/', '', $attr2);

	    return "<$element$attr2$xhtml_slash>";
	}

	function wp_kses_hair($attr, $allowed_protocols) {
	    $attrarr = array();
	    $mode = 0;
	    $attrname = '';
	    $uris = array('xmlns', 'profile', 'href', 'src', 'cite', 'classid', 'codebase', 'data', 'usemap', 'longdesc', 'action');

	    // Loop through the whole attribute list

	    while (strlen($attr) != 0) {
	        $working = 0; // Was the last operation successful?

	        switch ($mode) {
	            case 0 : // attribute name, href for instance

	                if ( preg_match('/^([-a-zA-Z:]+)/', $attr, $match ) ) {
	                    $attrname = $match[1];
	                    $working = $mode = 1;
	                    $attr = preg_replace( '/^[-a-zA-Z:]+/', '', $attr );
	                }

	                break;

	            case 1 : // equals sign or valueless ("selected")

	                if (preg_match('/^\s*=\s*/', $attr)) // equals sign
	                    {
	                    $working = 1;
	                    $mode = 2;
	                    $attr = preg_replace('/^\s*=\s*/', '', $attr);
	                    break;
	                }

	                if (preg_match('/^\s+/', $attr)) // valueless
	                    {
	                    $working = 1;
	                    $mode = 0;
	                    if(false === array_key_exists($attrname, $attrarr)) {
	                        $attrarr[$attrname] = array ('name' => $attrname, 'value' => '', 'whole' => $attrname, 'vless' => 'y');
	                    }
	                    $attr = preg_replace('/^\s+/', '', $attr);
	                }

	                break;

	            case 2 : // attribute value, a URL after href= for instance

	                if (preg_match('%^"([^"]*)"(\s+|/?$)%', $attr, $match))
	                    // "value"
	                    {
	                    $thisval = $match[1];
	                    if ( in_array(strtolower($attrname), $uris) )
	                        $thisval = $this->wp_kses_bad_protocol($thisval, $allowed_protocols);

	                    if(false === array_key_exists($attrname, $attrarr)) {
	                        $attrarr[$attrname] = array ('name' => $attrname, 'value' => $thisval, 'whole' => "$attrname=\"$thisval\"", 'vless' => 'n');
	                    }
	                    $working = 1;
	                    $mode = 0;
	                    $attr = preg_replace('/^"[^"]*"(\s+|$)/', '', $attr);
	                    break;
	                }

	                if (preg_match("%^'([^']*)'(\s+|/?$)%", $attr, $match))
	                    // 'value'
	                    {
	                    $thisval = $match[1];
	                    if ( in_array(strtolower($attrname), $uris) )
	                        $thisval = $this->wp_kses_bad_protocol($thisval, $allowed_protocols);

	                    if(false === array_key_exists($attrname, $attrarr)) {
	                        $attrarr[$attrname] = array ('name' => $attrname, 'value' => $thisval, 'whole' => "$attrname='$thisval'", 'vless' => 'n');
	                    }
	                    $working = 1;
	                    $mode = 0;
	                    $attr = preg_replace("/^'[^']*'(\s+|$)/", '', $attr);
	                    break;
	                }

	                if (preg_match("%^([^\s\"']+)(\s+|/?$)%", $attr, $match))
	                    // value
	                    {
	                    $thisval = $match[1];
	                    if ( in_array(strtolower($attrname), $uris) )
	                        $thisval = $this->wp_kses_bad_protocol($thisval, $allowed_protocols);

	                    if(false === array_key_exists($attrname, $attrarr)) {
	                        $attrarr[$attrname] = array ('name' => $attrname, 'value' => $thisval, 'whole' => "$attrname=\"$thisval\"", 'vless' => 'n');
	                    }
	                    // We add quotes to conform to W3C's HTML spec.
	                    $working = 1;
	                    $mode = 0;
	                    $attr = preg_replace("%^[^\s\"']+(\s+|$)%", '', $attr);
	                }

	                break;
	        } // switch

	        if ($working == 0) // not well formed, remove and try again
	        {
	            $attr = $this->wp_kses_html_error($attr);
	            $mode = 0;
	        }
	    } // while

	    if ($mode == 1 && false === array_key_exists($attrname, $attrarr))
	        // special case, for when the attribute list ends with a valueless
	        // attribute like "selected"
	        $attrarr[$attrname] = array ('name' => $attrname, 'value' => '', 'whole' => $attrname, 'vless' => 'y');

	    return $attrarr;
	}

	function wp_kses_attr_check( &$name, &$value, &$whole, $vless, $element, $allowed_html ) {
	    $allowed_attr = $allowed_html[strtolower( $element )];

	    $name_low = strtolower( $name );
	    if ( ! isset( $allowed_attr[$name_low] ) || '' == $allowed_attr[$name_low] ) {
	        $name = $value = $whole = '';
	        return false;
	    }

	    if ( 'style' == $name_low ) {
	        $new_value = $this->safecss_filter_attr( $value );

	        if ( empty( $new_value ) ) {
	            $name = $value = $whole = '';
	            return false;
	        }

	        $whole = str_replace( $value, $new_value, $whole );
	        $value = $new_value;
	    }

	    if ( is_array( $allowed_attr[$name_low] ) ) {
	        // there are some checks
	        foreach ( $allowed_attr[$name_low] as $currkey => $currval ) {
	            if ( ! $this->wp_kses_check_attr_val( $value, $vless, $currkey, $currval ) ) {
	                $name = $value = $whole = '';
	                return false;
	            }
	        }
	    }

	    return true;
	}

	function wp_kses_allowed_html( $context = '' ) {
	    global $allowedposttags, $allowedtags, $allowedentitynames;

	    if ( is_array( $context ) ) {
	        /**
	         * Filters HTML elements allowed for a given context.
	         *
	         * @since 3.5.0
	         *
	         * @param string $tags    Allowed tags, attributes, and/or entities.
	         * @param string $context Context to judge allowed tags by. Allowed values are 'post',
	         *                        'data', 'strip', 'entities', 'explicit', or the name of a filter.
	         */
	        return $this->apply_filters( 'wp_kses_allowed_html', $context, 'explicit' );
	    }

	    switch ( $context ) {
	        case 'post':
	            /** This filter is documented in wp-includes/kses.php */
	            return $this->apply_filters( 'wp_kses_allowed_html', $allowedposttags, $context );

	        case 'user_description':
	        case 'pre_user_description':
	            $tags = $allowedtags;
	            $tags['a']['rel'] = true;
	            /** This filter is documented in wp-includes/kses.php */
	            return $this->apply_filters( 'wp_kses_allowed_html', $tags, $context );

	        case 'strip':
	            /** This filter is documented in wp-includes/kses.php */
	            return $this->apply_filters( 'wp_kses_allowed_html', array(), $context );

	        case 'entities':
	            /** This filter is documented in wp-includes/kses.php */
	            return $this->apply_filters( 'wp_kses_allowed_html', $allowedentitynames, $context);

	        case 'data':
	        default:
	            /** This filter is documented in wp-includes/kses.php */
	            return $this->apply_filters( 'wp_kses_allowed_html', $allowedtags, $context );
	    }
	}

	function wp_kses_stripslashes($string) {
	    return preg_replace('%\\\\"%', '"', $string);
	}



	function wp_kses_normalize_entities($string) {
	    // Disarm all entities by converting & to &amp;
	    $string = str_replace('&', '&amp;', $string);

	    // Change back the allowed entities in our entity whitelist
	    $string = preg_replace_callback('/&amp;([A-Za-z]{2,8}[0-9]{0,2});/', 'wp_data_validation::wp_kses_named_entities', $string);
	    $string = preg_replace_callback('/&amp;#(0*[0-9]{1,7});/', 'wp_data_validation::wp_kses_normalize_entities2', $string);
	    $string = preg_replace_callback('/&amp;#[Xx](0*[0-9A-Fa-f]{1,6});/', 'wp_data_validation::wp_kses_normalize_entities3', $string);

	    return $string;
	}

	function wp_kses_named_entities($matches) {
	    global $allowedentitynames;

	    if ( empty($matches[1]) )
	        return '';

	    $i = $matches[1];
	    return ( ! in_array( $i, $allowedentitynames ) ) ? "&amp;$i;" : "&$i;";
	}

	function wp_kses_normalize_entities2($matches) {
	    if ( empty($matches[1]) )
	        return '';

	    $i = $matches[1];
	    if ( $this->valid_unicode($i)) {
	        $i = str_pad(ltrim($i,'0'), 3, '0', STR_PAD_LEFT);
	        $i = "&#$i;";
	    } else {
	        $i = "&amp;#$i;";
	    }

	    return $i;
	}

	function wp_kses_normalize_entities3($matches) {
	    if ( empty($matches[1]) )
	        return '';

	    $hexchars = $matches[1];
	    return ( ! $this->valid_unicode( hexdec( $hexchars ) ) ) ? "&amp;#x$hexchars;" : '&#x'.ltrim($hexchars,'0').';';
	}

	function _wp_specialchars( $string, $quote_style = ENT_NOQUOTES, $charset = false, $double_encode = false ) {
	    $string = (string) $string;

	    if ( 0 === strlen( $string ) )
	        return '';

	    // Don't bother if there are no specialchars - saves some processing
	    if ( ! preg_match( '/[&<>"\']/', $string ) )
	        return $string;

	    // Account for the previous behaviour of the function when the $quote_style is not an accepted value
	    if ( empty( $quote_style ) )
	        $quote_style = ENT_NOQUOTES;
	    elseif ( ! in_array( $quote_style, array( 0, 2, 3, 'single', 'double' ), true ) )
	        $quote_style = ENT_QUOTES;

	    // Store the site charset as a static to avoid multiple calls to wp_load_alloptions()
	    if ( ! $charset ) {
	        static $_charset = null;
	        if ( ! isset( $_charset ) ) {
	            $_charset = 'UTF-8';
	        }
	        $charset = $_charset;
	    }

	    if ( in_array( $charset, array( 'utf8', 'utf-8', 'UTF8' ) ) )
	        $charset = 'UTF-8';

	    $_quote_style = $quote_style;

	    if ( $quote_style === 'double' ) {
	        $quote_style = ENT_COMPAT;
	        $_quote_style = ENT_COMPAT;
	    } elseif ( $quote_style === 'single' ) {
	        $quote_style = ENT_NOQUOTES;
	    }

	    if ( ! $double_encode ) {
	        // Guarantee every &entity; is valid, convert &garbage; into &amp;garbage;
	        // This is required for PHP < 5.4.0 because ENT_HTML401 flag is unavailable.
	        $string = $this->wp_kses_normalize_entities( $string );
	    }

	    $string = @htmlspecialchars( $string, $quote_style, $charset, $double_encode );

	    // Back-compat.
	    if ( 'single' === $_quote_style )
	        $string = str_replace( "'", '&#039;', $string );

	    return $string;
	}


	function esc_html( $text ) {
	    $safe_text = $this->wp_check_invalid_utf8( $text );
	    $safe_text = $this->_wp_specialchars( $safe_text, ENT_QUOTES );
	    /**
	     * Filters a string cleaned and escaped for output in HTML.
	     *
	     * Text passed to esc_html() is stripped of invalid or special characters
	     * before output.
	     *
	     * @since 2.8.0
	     *
	     * @param string $safe_text The text after it has been escaped.
	     * @param string $text      The text prior to being escaped.
	     */
	    return $this->apply_filters( 'esc_html', $safe_text, $text );
	}



	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************

	function _deep_replace( $search, $subject ) {
	    $subject = (string) $subject;

	    $count = 1;
	    while ( $count ) {
	        $subject = str_replace( $search, '', $subject, $count );
	    }

	    return $subject;
	}

	function wp_allowed_protocols() {
	    static $protocols = array();

	    if ( empty( $protocols ) ) {
	        $protocols = array( 'http', 'https', 'ftp', 'ftps', 'mailto', 'news', 'irc', 'gopher', 'nntp', 'feed', 'telnet', 'mms', 'rtsp', 'svn', 'tel', 'fax', 'xmpp', 'webcal' );

	        /**
	         * Filters the list of protocols allowed in HTML attributes.
	         *
	         * @since 3.0.0
	         *
	         * @param array $protocols Array of allowed protocols e.g. 'http', 'ftp', 'tel', and more.
	         */
	        $protocols = $this->apply_filters( 'kses_allowed_protocols', $protocols );
	    }

	    return $protocols;
	}

	function wp_kses_no_null( $string, $options = null ) {
	    if ( ! isset( $options['slash_zero'] ) ) {
	        $options = array( 'slash_zero' => 'remove' );
	    }

	    $string = preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $string );
	    if ( 'remove' == $options['slash_zero'] ) {
	        $string = preg_replace( '/\\\\+0+/', '', $string );
	    }

	    return $string;
	}

	function wp_kses_js_entities($string) {
	    return preg_replace('%&\s*\{[^}]*(\}\s*;?|$)%', '', $string);
	}

	function wp_kses_hook( $string, $allowed_html, $allowed_protocols ) {
	    /**
	     * Filters content to be run through kses.
	     *
	     * @since 2.3.0
	     *
	     * @param string $string            Content to run through kses.
	     * @param array  $allowed_html      Allowed HTML elements.
	     * @param array  $allowed_protocols Allowed protocol in links.
	     */
	    return $this->apply_filters( 'pre_kses', $string, $allowed_html, $allowed_protocols );
	}

	function wp_kses_bad_protocol($string, $allowed_protocols) {
	    $string = $this->wp_kses_no_null($string);
	    $iterations = 0;

	    do {
	        $original_string = $string;
	        $string = $this->wp_kses_bad_protocol_once($string, $allowed_protocols);
	    } while ( $original_string != $string && ++$iterations < 6 );

	    if ( $original_string != $string )
	        return '';

	    return $string;
	}

	function wp_kses_bad_protocol_once2( $string, $allowed_protocols ) {
	    $string2 = $this->wp_kses_decode_entities($string);
	    $string2 = preg_replace('/\s/', '', $string2);
	    $string2 = $this->wp_kses_no_null($string2);
	    $string2 = strtolower($string2);

	    $allowed = false;
	    foreach ( (array) $allowed_protocols as $one_protocol )
	        if ( strtolower($one_protocol) == $string2 ) {
	            $allowed = true;
	            break;
	        }

	    if ($allowed)
	        return "$string2:";
	    else
	        return '';
	}

	function _wp_kses_decode_entities_chr( $match ) {
	    return chr( $match[1] );
	}

	function _wp_kses_decode_entities_chr_hexdec( $match ) {
	    return chr( hexdec( $match[1] ) );
	}

	function wp_kses_decode_entities($string) {
	    $string = preg_replace_callback('/&#([0-9]+);/', 'wp_data_validation::_wp_kses_decode_entities_chr', $string);
	    $string = preg_replace_callback('/&#[Xx]([0-9A-Fa-f]+);/', 'wp_data_validation::_wp_kses_decode_entities_chr_hexdec', $string);

	    return $string;
	}

	function wp_kses_bad_protocol_once($string, $allowed_protocols, $count = 1 ) {
	    $string2 = preg_split( '/:|&#0*58;|&#x0*3a;/i', $string, 2 );
	    if ( isset($string2[1]) && ! preg_match('%/\?%', $string2[0]) ) {
	        $string = trim( $string2[1] );
	        $protocol = $this->wp_kses_bad_protocol_once2( $string2[0], $allowed_protocols );
	        if ( 'feed:' == $protocol ) {
	            if ( $count > 2 )
	                return '';
	            $string = $this->wp_kses_bad_protocol_once( $string, $allowed_protocols, ++$count );
	            if ( empty( $string ) )
	                return $string;
	        }
	        $string = $protocol . $string;
	    }

	    return $string;
	}

	function esc_url( $url, $protocols = null, $_context = 'display' ) {
	    $original_url = $url;

	    if ( '' == $url )
	        return $url;

	    $url = str_replace( ' ', '%20', $url );
	    $url = preg_replace('|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\[\]\\x80-\\xff]|i', '', $url);

	    if ( '' === $url ) {
	        return $url;
	    }

	    if ( 0 !== stripos( $url, 'mailto:' ) ) {
	        $strip = array('%0d', '%0a', '%0D', '%0A');
	        $url = $this->_deep_replace($strip, $url);
	    }

	    $url = str_replace(';//', '://', $url);
	    /* If the URL doesn't appear to contain a scheme, we
	     * presume it needs http:// prepended (unless a relative
	     * link starting with /, # or ? or a php file).
	     */
	    if ( strpos($url, ':') === false && ! in_array( $url[0], array( '/', '#', '?' ) ) &&
	        ! preg_match('/^[a-z0-9-]+?\.php/i', $url) )
	        $url = 'http://' . $url;

	    // Replace ampersands and single quotes only when displaying.
	    if ( 'display' == $_context ) {
	        $url = $this->wp_kses_normalize_entities( $url );
	        $url = str_replace( '&amp;', '&#038;', $url );
	        $url = str_replace( "'", '&#039;', $url );
	    }

	    if ( ( false !== strpos( $url, '[' ) ) || ( false !== strpos( $url, ']' ) ) ) {

	        $parsed = $this->wp_parse_url( $url );
	        $front  = '';

	        if ( isset( $parsed['scheme'] ) ) {
	            $front .= $parsed['scheme'] . '://';
	        } elseif ( '/' === $url[0] ) {
	            $front .= '//';
	        }

	        if ( isset( $parsed['user'] ) ) {
	            $front .= $parsed['user'];
	        }

	        if ( isset( $parsed['pass'] ) ) {
	            $front .= ':' . $parsed['pass'];
	        }

	        if ( isset( $parsed['user'] ) || isset( $parsed['pass'] ) ) {
	            $front .= '@';
	        }

	        if ( isset( $parsed['host'] ) ) {
	            $front .= $parsed['host'];
	        }

	        if ( isset( $parsed['port'] ) ) {
	            $front .= ':' . $parsed['port'];
	        }

	        $end_dirty = str_replace( $front, '', $url );
	        $end_clean = str_replace( array( '[', ']' ), array( '%5B', '%5D' ), $end_dirty );
	        $url       = str_replace( $end_dirty, $end_clean, $url );

	    }

	    if ( '/' === $url[0] ) {
	        $good_protocol_url = $url;
	    } else {
	        if ( ! is_array( $protocols ) )
	            $protocols = $this->wp_allowed_protocols();
	        $good_protocol_url = $this->wp_kses_bad_protocol( $url, $protocols );
	        if ( strtolower( $good_protocol_url ) != strtolower( $url ) )
	            return '';
	    }

	    /**
	     * Filters a string cleaned and escaped for output as a URL.
	     *
	     * @since 2.3.0
	     *
	     * @param string $good_protocol_url The cleaned URL to be returned.
	     * @param string $original_url      The URL prior to cleaning.
	     * @param string $_context          If 'display', replace ampersands and single quotes only.
	     */
	    return $this->apply_filters( 'clean_url', $good_protocol_url, $original_url, $_context );
	}

	function wp_parse_url( $url ) {
	    $parts = @parse_url( $url );
	    if ( ! $parts ) {
	        // < PHP 5.4.7 compat, trouble with relative paths including a scheme break in the path
	        if ( '/' == $url[0] && false !== strpos( $url, '://' ) ) {
	            // Since we know it's a relative path, prefix with a scheme/host placeholder and try again
	            if ( ! $parts = @parse_url( 'placeholder://placeholder' . $url ) ) {
	                return $parts;
	            }
	            // Remove the placeholder values
	            unset( $parts['scheme'], $parts['host'] );
	        } else {
	            return $parts;
	        }
	    }

	    // < PHP 5.4.7 compat, doesn't detect schemeless URL's host field
	    if ( '//' == substr( $url, 0, 2 ) && ! isset( $parts['host'] ) ) {
	        $path_parts = explode( '/', substr( $parts['path'], 2 ), 2 );
	        $parts['host'] = $path_parts[0];
	        if ( isset( $path_parts[1] ) ) {
	            $parts['path'] = '/' . $path_parts[1];
	        } else {
	            unset( $parts['path'] );
	        }
	    }

	    return $parts;
	}


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************

	function esc_js( $text ) {
	    $safe_text = $this->wp_check_invalid_utf8( $text );
	    $safe_text = $this->_wp_specialchars( $safe_text, ENT_COMPAT );
	    $safe_text = preg_replace( '/&#(x)?0*(?(1)27|39);?/i', "'", stripslashes( $safe_text ) );
	    $safe_text = str_replace( "\r", '', $safe_text );
	    $safe_text = str_replace( "\n", '\\n', addslashes( $safe_text ) );
	    /**
	     * Filters a string cleaned and escaped for output in JavaScript.
	     *
	     * Text passed to esc_js() is stripped of invalid or special characters,
	     * and properly slashed for output.
	     *
	     * @since 2.0.6
	     *
	     * @param string $safe_text The text after it has been escaped.
	     * @param string $text      The text prior to being escaped.
	     */
	    return $this->apply_filters( 'js_escape', $safe_text, $text );
	}


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	// Always use when escaping HTML attributes (especially form values) such as alt, value, title, etc. To escape the value of a translation use esc_attr__() instead; to escape, translate and echo, use esc_attr_e().
	function esc_attr( $text ) {
	    $safe_text = $this->wp_check_invalid_utf8( $text );
	    $safe_text = $this->_wp_specialchars( $safe_text, ENT_QUOTES );
	    /**
	     * Filters a string cleaned and escaped for output in an HTML attribute.
	     *
	     * Text passed to esc_attr() is stripped of invalid or special characters
	     * before output.
	     *
	     * @since 2.0.6
	     *
	     * @param string $safe_text The text after it has been escaped.
	     * @param string $text      The text prior to being escaped.
	     */
	    return $this->apply_filters( 'attribute_escape', $safe_text, $text );
	}

	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	function esc_textarea( $text ) {
	    $safe_text = htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
	    /**
	     * Filters a string cleaned and escaped for output in a textarea element.
	     *
	     * @since 3.1.0
	     *
	     * @param string $safe_text The text after it has been escaped.
	     * @param string $text      The text prior to being escaped.
	     */
	    return $this->apply_filters( 'esc_textarea', $safe_text, $text );
	}


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	function sanitize_email( $email ) {
	    // Test for the minimum length the email can be
	    if ( strlen( $email ) < 3 ) {
	        /**
	         * Filters a sanitized email address.
	         *
	         * This filter is evaluated under several contexts, including 'email_too_short',
	         * 'email_no_at', 'local_invalid_chars', 'domain_period_sequence', 'domain_period_limits',
	         * 'domain_no_periods', 'domain_no_valid_subs', or no context.
	         *
	         * @since 2.8.0
	         *
	         * @param string $email   The sanitized email address.
	         * @param string $email   The email address, as provided to sanitize_email().
	         * @param string $message A message to pass to the user.
	         */
	        return $this->apply_filters( 'sanitize_email', '', $email, 'email_too_short' );
	    }

	    // Test for an @ character after the first position
	    if ( strpos( $email, '@', 1 ) === false ) {
	        /** This filter is documented in wp-includes/formatting.php */
	        return $this->apply_filters( 'sanitize_email', '', $email, 'email_no_at' );
	    }

	    // Split out the local and domain parts
	    list( $local, $domain ) = explode( '@', $email, 2 );

	    // LOCAL PART
	    // Test for invalid characters
	    $local = preg_replace( '/[^a-zA-Z0-9!#$%&\'*+\/=?^_`{|}~\.-]/', '', $local );
	    if ( '' === $local ) {
	        /** This filter is documented in wp-includes/formatting.php */
	        return $this->apply_filters( 'sanitize_email', '', $email, 'local_invalid_chars' );
	    }

	    // DOMAIN PART
	    // Test for sequences of periods
	    $domain = preg_replace( '/\.{2,}/', '', $domain );
	    if ( '' === $domain ) {
	        /** This filter is documented in wp-includes/formatting.php */
	        return $this->apply_filters( 'sanitize_email', '', $email, 'domain_period_sequence' );
	    }

	    // Test for leading and trailing periods and whitespace
	    $domain = trim( $domain, " \t\n\r\0\x0B." );
	    if ( '' === $domain ) {
	        /** This filter is documented in wp-includes/formatting.php */
	        return $this->apply_filters( 'sanitize_email', '', $email, 'domain_period_limits' );
	    }

	    // Split the domain into subs
	    $subs = explode( '.', $domain );

	    // Assume the domain will have at least two subs
	    if ( 2 > count( $subs ) ) {
	        /** This filter is documented in wp-includes/formatting.php */
	        return $this->apply_filters( 'sanitize_email', '', $email, 'domain_no_periods' );
	    }

	    // Create an array that will contain valid subs
	    $new_subs = array();

	    // Loop through each sub
	    foreach ( $subs as $sub ) {
	        // Test for leading and trailing hyphens
	        $sub = trim( $sub, " \t\n\r\0\x0B-" );

	        // Test for invalid characters
	        $sub = preg_replace( '/[^a-z0-9-]+/i', '', $sub );

	        // If there's anything left, add it to the valid subs
	        if ( '' !== $sub ) {
	            $new_subs[] = $sub;
	        }
	    }

	    // If there aren't 2 or more valid subs
	    if ( 2 > count( $new_subs ) ) {
	        /** This filter is documented in wp-includes/formatting.php */
	        return $this->apply_filters( 'sanitize_email', '', $email, 'domain_no_valid_subs' );
	    }

	    // Join valid subs into the new domain
	    $domain = join( '.', $new_subs );

	    // Put the email back together
	    $email = $local . '@' . $domain;

	    // Congratulations your email made it!
	    /** This filter is documented in wp-includes/formatting.php */
	    return $this->apply_filters( 'sanitize_email', $email, $email, null );
	}


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************

	function sanitize_file_name( $filename ) {
	    $filename_raw = $filename;
	    $special_chars = array("?", "[", "]", "/", "\\", "=", "<", ">", ":", ";", ",", "'", "\"", "&", "$", "#", "*", "(", ")", "|", "~", "`", "!", "{", "}", "%", "+", chr(0));
	    /**
	     * Filters the list of characters to remove from a filename.
	     *
	     * @since 2.8.0
	     *
	     * @param array  $special_chars Characters to remove.
	     * @param string $filename_raw  Filename as it was passed into sanitize_file_name().
	     */
	    $special_chars = $this->apply_filters( 'sanitize_file_name_chars', $special_chars, $filename_raw );
	    $filename = preg_replace( "#\x{00a0}#siu", ' ', $filename );
	    $filename = str_replace( $special_chars, '', $filename );
	    $filename = str_replace( array( '%20', '+' ), '-', $filename );
	    $filename = preg_replace( '/[\r\n\t -]+/', '-', $filename );
	    $filename = trim( $filename, '.-_' );

	    if ( false === strpos( $filename, '.' ) ) {
	        $mime_types = $this->wp_get_mime_types();
	        $filetype = $this->wp_check_filetype( 'test.' . $filename, $mime_types );
	        if ( $filetype['ext'] === $filename ) {
	            $filename = 'unnamed-file.' . $filetype['ext'];
	        }
	    }

	    // Split the filename into a base and extension[s]
	    $parts = explode('.', $filename);

	    // Return if only one extension
	    if ( count( $parts ) <= 2 ) {
	        /**
	         * Filters a sanitized filename string.
	         *
	         * @since 2.8.0
	         *
	         * @param string $filename     Sanitized filename.
	         * @param string $filename_raw The filename prior to sanitization.
	         */
	        return $this->apply_filters( 'sanitize_file_name', $filename, $filename_raw );
	    }

	    // Process multiple extensions
	    $filename = array_shift($parts);
	    $extension = array_pop($parts);
	    $mimes = $this->get_allowed_mime_types();

	    /*
	     * Loop over any intermediate extensions. Postfix them with a trailing underscore
	     * if they are a 2 - 5 character long alpha string not in the extension whitelist.
	     */
	    foreach ( (array) $parts as $part) {
	        $filename .= '.' . $part;

	        if ( preg_match("/^[a-zA-Z]{2,5}\d?$/", $part) ) {
	            $allowed = false;
	            foreach ( $mimes as $ext_preg => $mime_match ) {
	                $ext_preg = '!^(' . $ext_preg . ')$!i';
	                if ( preg_match( $ext_preg, $part ) ) {
	                    $allowed = true;
	                    break;
	                }
	            }
	            if ( !$allowed )
	                $filename .= '_';
	        }
	    }
	    $filename .= '.' . $extension;
	    /** This filter is documented in wp-includes/formatting.php */
	    return $this->apply_filters('sanitize_file_name', $filename, $filename_raw);
	}

	function wp_get_mime_types() {
	    /**
	     * Filters the list of mime types and file extensions.
	     *
	     * This filter should be used to add, not remove, mime types. To remove
	     * mime types, use the {@see 'upload_mimes'} filter.
	     *
	     * @since 3.5.0
	     *
	     * @param array $wp_get_mime_types Mime types keyed by the file extension regex
	     *                                 corresponding to those types.
	     */
	    return $this->apply_filters( 'mime_types', array(
	    // Image formats.
	    'jpg|jpeg|jpe' => 'image/jpeg',
	    'gif' => 'image/gif',
	    'png' => 'image/png',
	    'bmp' => 'image/bmp',
	    'tiff|tif' => 'image/tiff',
	    'ico' => 'image/x-icon',
	    // Video formats.
	    'asf|asx' => 'video/x-ms-asf',
	    'wmv' => 'video/x-ms-wmv',
	    'wmx' => 'video/x-ms-wmx',
	    'wm' => 'video/x-ms-wm',
	    'avi' => 'video/avi',
	    'divx' => 'video/divx',
	    'flv' => 'video/x-flv',
	    'mov|qt' => 'video/quicktime',
	    'mpeg|mpg|mpe' => 'video/mpeg',
	    'mp4|m4v' => 'video/mp4',
	    'ogv' => 'video/ogg',
	    'webm' => 'video/webm',
	    'mkv' => 'video/x-matroska',
	    '3gp|3gpp' => 'video/3gpp', // Can also be audio
	    '3g2|3gp2' => 'video/3gpp2', // Can also be audio
	    // Text formats.
	    'txt|asc|c|cc|h|srt' => 'text/plain',
	    'csv' => 'text/csv',
	    'tsv' => 'text/tab-separated-values',
	    'ics' => 'text/calendar',
	    'rtx' => 'text/richtext',
	    'css' => 'text/css',
	    'htm|html' => 'text/html',
	    'vtt' => 'text/vtt',
	    'dfxp' => 'application/ttaf+xml',
	    // Audio formats.
	    'mp3|m4a|m4b' => 'audio/mpeg',
	    'ra|ram' => 'audio/x-realaudio',
	    'wav' => 'audio/wav',
	    'ogg|oga' => 'audio/ogg',
	    'mid|midi' => 'audio/midi',
	    'wma' => 'audio/x-ms-wma',
	    'wax' => 'audio/x-ms-wax',
	    'mka' => 'audio/x-matroska',
	    // Misc application formats.
	    'rtf' => 'application/rtf',
	    'js' => 'application/javascript',
	    'pdf' => 'application/pdf',
	    'swf' => 'application/x-shockwave-flash',
	    'class' => 'application/java',
	    'tar' => 'application/x-tar',
	    'zip' => 'application/zip',
	    'gz|gzip' => 'application/x-gzip',
	    'rar' => 'application/rar',
	    '7z' => 'application/x-7z-compressed',
	    'exe' => 'application/x-msdownload',
	    'psd' => 'application/octet-stream',
	    'xcf' => 'application/octet-stream',
	    // MS Office formats.
	    'doc' => 'application/msword',
	    'pot|pps|ppt' => 'application/vnd.ms-powerpoint',
	    'wri' => 'application/vnd.ms-write',
	    'xla|xls|xlt|xlw' => 'application/vnd.ms-excel',
	    'mdb' => 'application/vnd.ms-access',
	    'mpp' => 'application/vnd.ms-project',
	    'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
	    'docm' => 'application/vnd.ms-word.document.macroEnabled.12',
	    'dotx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.template',
	    'dotm' => 'application/vnd.ms-word.template.macroEnabled.12',
	    'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
	    'xlsm' => 'application/vnd.ms-excel.sheet.macroEnabled.12',
	    'xlsb' => 'application/vnd.ms-excel.sheet.binary.macroEnabled.12',
	    'xltx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.template',
	    'xltm' => 'application/vnd.ms-excel.template.macroEnabled.12',
	    'xlam' => 'application/vnd.ms-excel.addin.macroEnabled.12',
	    'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
	    'pptm' => 'application/vnd.ms-powerpoint.presentation.macroEnabled.12',
	    'ppsx' => 'application/vnd.openxmlformats-officedocument.presentationml.slideshow',
	    'ppsm' => 'application/vnd.ms-powerpoint.slideshow.macroEnabled.12',
	    'potx' => 'application/vnd.openxmlformats-officedocument.presentationml.template',
	    'potm' => 'application/vnd.ms-powerpoint.template.macroEnabled.12',
	    'ppam' => 'application/vnd.ms-powerpoint.addin.macroEnabled.12',
	    'sldx' => 'application/vnd.openxmlformats-officedocument.presentationml.slide',
	    'sldm' => 'application/vnd.ms-powerpoint.slide.macroEnabled.12',
	    'onetoc|onetoc2|onetmp|onepkg' => 'application/onenote',
	    'oxps' => 'application/oxps',
	    'xps' => 'application/vnd.ms-xpsdocument',
	    // OpenOffice formats.
	    'odt' => 'application/vnd.oasis.opendocument.text',
	    'odp' => 'application/vnd.oasis.opendocument.presentation',
	    'ods' => 'application/vnd.oasis.opendocument.spreadsheet',
	    'odg' => 'application/vnd.oasis.opendocument.graphics',
	    'odc' => 'application/vnd.oasis.opendocument.chart',
	    'odb' => 'application/vnd.oasis.opendocument.database',
	    'odf' => 'application/vnd.oasis.opendocument.formula',
	    // WordPerfect formats.
	    'wp|wpd' => 'application/wordperfect',
	    // iWork formats.
	    'key' => 'application/vnd.apple.keynote',
	    'numbers' => 'application/vnd.apple.numbers',
	    'pages' => 'application/vnd.apple.pages',
	    ) );
	}


	function wp_check_filetype( $filename, $mimes = null ) {
	    if ( empty($mimes) )
	        $mimes = $this->get_allowed_mime_types();
	    $type = false;
	    $ext = false;

	    foreach ( $mimes as $ext_preg => $mime_match ) {
	        $ext_preg = '!\.(' . $ext_preg . ')$!i';
	        if ( preg_match( $ext_preg, $filename, $ext_matches ) ) {
	            $type = $mime_match;
	            $ext = $ext_matches[1];
	            break;
	        }
	    }

	    return compact( 'ext', 'type' );
	}



	function get_allowed_mime_types( $user = null ) {
	    $t = $this->wp_get_mime_types();

	    unset( $t['swf'], $t['exe'] );
	    if ( function_exists( 'current_user_can' ) )
	        $unfiltered = $user ? $this->user_can( $user, 'unfiltered_html' ) : $this->current_user_can( 'unfiltered_html' );

	    if ( empty( $unfiltered ) )
	        unset( $t['htm|html'] );

	    /**
	     * Filters list of allowed mime types and file extensions.
	     *
	     * @since 2.0.0
	     *
	     * @param array            $t    Mime types keyed by the file extension regex corresponding to
	     *                               those types. 'swf' and 'exe' removed from full list. 'htm|html' also
	     *                               removed depending on '$user' capabilities.
	     * @param int|WP_User|null $user User ID, User object or null if not provided (indicates current user).
	     */
	    return $this->apply_filters( 'upload_mimes', $t, $user );
	}



	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	function sanitize_html_class( $class, $fallback = '' ) {
	    //Strip out any % encoded octets
	    $sanitized = preg_replace( '|%[a-fA-F0-9][a-fA-F0-9]|', '', $class );

	    //Limit to A-Z,a-z,0-9,_,-
	    $sanitized = preg_replace( '/[^A-Za-z0-9_-]/', '', $sanitized );

	    if ( '' == $sanitized && $fallback ) {
	        return $this->sanitize_html_class( $fallback );
	    }
	    /**
	     * Filters a sanitized HTML class string.
	     *
	     * @since 2.8.0
	     *
	     * @param string $sanitized The sanitized HTML class.
	     * @param string $class     HTML class before sanitization.
	     * @param string $fallback  The fallback string.
	     */
	    return $this->apply_filters( 'sanitize_html_class', $sanitized, $class, $fallback );
	}


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	function esc_url_raw( $url, $protocols = null ) {
	    return $this->esc_url( $url, $protocols, 'db' );
	}


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	function urlencode_deep( $value ) {
	    return $this->map_deep( $value, 'urlencode' );
	}

	function map_deep( $value, $callback ) {
	    if ( is_array( $value ) ) {
	        foreach ( $value as $index => $item ) {
	            $value[ $index ] = $this->map_deep( $item, $callback );
	        }
	    } elseif ( is_object( $value ) ) {
	        $object_vars = get_object_vars( $value );
	        foreach ( $object_vars as $property_name => $property_value ) {
	            $value->$property_name = $this->map_deep( $property_value, $callback );
	        }
	    } else {
	        $value = call_user_func( $callback, $value );
	    }

	    return $value;
	}


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	function wp_redirect($location, $status = 302) {
	    global $is_IIS;

	    /**
	     * Filters the redirect location.
	     *
	     * @since 2.1.0
	     *
	     * @param string $location The path to redirect to.
	     * @param int    $status   Status code to use.
	     */
	    $location = $this->apply_filters( 'wp_redirect', $location, $status );

	    /**
	     * Filters the redirect status code.
	     *
	     * @since 2.3.0
	     *
	     * @param int    $status   Status code to use.
	     * @param string $location The path to redirect to.
	     */
	    $status = $this->apply_filters( 'wp_redirect_status', $status, $location );

	    if ( ! $location )
	        return false;

	    $location = $this->wp_sanitize_redirect($location);

	    if ( !$is_IIS && PHP_SAPI != 'cgi-fcgi' )
	        $this->status_header($status); // This causes problems on IIS and some FastCGI setups

	    header("Location: $location", true, $status);

	    return true;
	}

	function wp_sanitize_redirect($location) {
	    $regex = '/
	        (
	            (?: [\xC2-\xDF][\x80-\xBF]        # double-byte sequences   110xxxxx 10xxxxxx
	            |   \xE0[\xA0-\xBF][\x80-\xBF]    # triple-byte sequences   1110xxxx 10xxxxxx * 2
	            |   [\xE1-\xEC][\x80-\xBF]{2}
	            |   \xED[\x80-\x9F][\x80-\xBF]
	            |   [\xEE-\xEF][\x80-\xBF]{2}
	            |   \xF0[\x90-\xBF][\x80-\xBF]{2} # four-byte sequences   11110xxx 10xxxxxx * 3
	            |   [\xF1-\xF3][\x80-\xBF]{3}
	            |   \xF4[\x80-\x8F][\x80-\xBF]{2}
	        ){1,40}                              # ...one or more times
	        )/x';
	    $location = preg_replace_callback( $regex, 'wp_data_validation::_wp_sanitize_utf8_in_redirect', $location );
	    $location = preg_replace('|[^a-z0-9-~+_.?#=&;,/:%!*\[\]()@]|i', '', $location);
	    $location = $this->wp_kses_no_null($location);

	    // remove %0d and %0a from location
	    $strip = array('%0d', '%0a', '%0D', '%0A');
	    return $this->_deep_replace( $strip, $location );
	}

	function status_header( $code, $description = '' ) {
	    if ( ! $description ) {
	        $description = $this->get_status_header_desc( $code );
	    }

	    if ( empty( $description ) ) {
	        return;
	    }

	    $protocol = $this->wp_get_server_protocol();
	    $status_header = "$protocol $code $description";
	    if ( function_exists( 'apply_filters' ) )

	        /**
	         * Filters an HTTP status header.
	         *
	         * @since 2.2.0
	         *
	         * @param string $status_header HTTP status header.
	         * @param int    $code          HTTP status code.
	         * @param string $description   Description for the status code.
	         * @param string $protocol      Server protocol.
	         */
	        $status_header = $this->apply_filters( 'status_header', $status_header, $code, $description, $protocol );

	    @header( $status_header, true, $code );
	}

	function wp_get_server_protocol() {
	    $protocol = $_SERVER['SERVER_PROTOCOL'];
	    if ( ! in_array( $protocol, array( 'HTTP/1.1', 'HTTP/2', 'HTTP/2.0' ) ) ) {
	        $protocol = 'HTTP/1.0';
	    }
	    return $protocol;
	}

	function get_status_header_desc( $code ) {
	    global $wp_header_to_desc;

	    $code = $this->absint( $code );

	    if ( !isset( $wp_header_to_desc ) ) {
	        $wp_header_to_desc = array(
	            100 => 'Continue',
	            101 => 'Switching Protocols',
	            102 => 'Processing',

	            200 => 'OK',
	            201 => 'Created',
	            202 => 'Accepted',
	            203 => 'Non-Authoritative Information',
	            204 => 'No Content',
	            205 => 'Reset Content',
	            206 => 'Partial Content',
	            207 => 'Multi-Status',
	            226 => 'IM Used',

	            300 => 'Multiple Choices',
	            301 => 'Moved Permanently',
	            302 => 'Found',
	            303 => 'See Other',
	            304 => 'Not Modified',
	            305 => 'Use Proxy',
	            306 => 'Reserved',
	            307 => 'Temporary Redirect',
	            308 => 'Permanent Redirect',

	            400 => 'Bad Request',
	            401 => 'Unauthorized',
	            402 => 'Payment Required',
	            403 => 'Forbidden',
	            404 => 'Not Found',
	            405 => 'Method Not Allowed',
	            406 => 'Not Acceptable',
	            407 => 'Proxy Authentication Required',
	            408 => 'Request Timeout',
	            409 => 'Conflict',
	            410 => 'Gone',
	            411 => 'Length Required',
	            412 => 'Precondition Failed',
	            413 => 'Request Entity Too Large',
	            414 => 'Request-URI Too Long',
	            415 => 'Unsupported Media Type',
	            416 => 'Requested Range Not Satisfiable',
	            417 => 'Expectation Failed',
	            418 => 'I\'m a teapot',
	            421 => 'Misdirected Request',
	            422 => 'Unprocessable Entity',
	            423 => 'Locked',
	            424 => 'Failed Dependency',
	            426 => 'Upgrade Required',
	            428 => 'Precondition Required',
	            429 => 'Too Many Requests',
	            431 => 'Request Header Fields Too Large',
	            451 => 'Unavailable For Legal Reasons',

	            500 => 'Internal Server Error',
	            501 => 'Not Implemented',
	            502 => 'Bad Gateway',
	            503 => 'Service Unavailable',
	            504 => 'Gateway Timeout',
	            505 => 'HTTP Version Not Supported',
	            506 => 'Variant Also Negotiates',
	            507 => 'Insufficient Storage',
	            510 => 'Not Extended',
	            511 => 'Network Authentication Required',
	        );
	    }

	    if ( isset( $wp_header_to_desc[$code] ) )
	        return $wp_header_to_desc[$code];
	    else
	        return '';
	}

	function absint( $maybeint ) {
	    return abs( intval( $maybeint ) );
	}


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************

	function wp_safe_redirect($location, $status = 302) {

	    // Need to look at the URL the way it will end up in wp_redirect()
	    $location = $this->wp_sanitize_redirect($location);

	    /**
	     * Filters the redirect fallback URL for when the provided redirect is not safe (local).
	     *
	     * @since 4.3.0
	     *
	     * @param string $fallback_url The fallback URL to use by default.
	     * @param int    $status       The redirect status.
	     */
	    $location = $this->wp_validate_redirect( $location, $this->apply_filters( 'wp_safe_redirect_fallback', $this->admin_url(), $status ) );

	    $this->wp_redirect($location, $status);
	}

	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************


	// https://vip.wordpress.com/documentation/vip/best-practices/security/validating-sanitizing-escaping/#sanitizing-cleaning-user-input
	// actually removes all HTML markup, as well as extra whitespace. It leaves nothing but plain text.
	function sanitize_text_field( $str ) {
	    $filtered = $this->wp_check_invalid_utf8( $str );

	    if ( strpos($filtered, '<') !== false ) {
	        $filtered = $this->wp_pre_kses_less_than( $filtered );
	        // This will strip extra whitespace for us.
	        $filtered = $this->wp_strip_all_tags( $filtered, true );
	    } else {
	        $filtered = trim( preg_replace('/[\r\n\t ]+/', ' ', $filtered) );
	    }

	    $found = false;
	    while ( preg_match('/%[a-f0-9]{2}/i', $filtered, $match) ) {
	        $filtered = str_replace($match[0], '', $filtered);
	        $found = true;
	    }

	    if ( $found ) {
	        // Strip out the whitespace that may now exist after removing the octets.
	        $filtered = trim( preg_replace('/ +/', ' ', $filtered) );
	    }

	    /**
	     * Filters a sanitized text field string.
	     *
	     * @since 2.9.0
	     *
	     * @param string $filtered The sanitized string.
	     * @param string $str      The string prior to being sanitized.
	     */
	    return $this->apply_filters( 'sanitize_text_field', $filtered, $str );
	}






	// ********************
	// ********************
	// ********************
	// ********************
	// Verfügbare functions
	//
	//
	// esc_html() -> https://vip.wordpress.com/documentation/vip/best-practices/security/validating-sanitizing-escaping/#escaping-securing-output
	// esc_url() -> https://vip.wordpress.com/documentation/vip/best-practices/security/validating-sanitizing-escaping/#escaping-securing-output
	// esc_url_raw()
	// esc_js() -> https://vip.wordpress.com/documentation/vip/best-practices/security/validating-sanitizing-escaping/#escaping-securing-output
	// esc_attr() -> https://vip.wordpress.com/documentation/vip/best-practices/security/validating-sanitizing-escaping/#escaping-securing-output
	// esc_textarea()
	// wp_kses() -https://vip.wordpress.com/documentation/vip/best-practices/security/validating-sanitizing-escaping/#escaping-securing-output
	// wp_kses_post() -https://vip.wordpress.com/documentation/vip/best-practices/security/validating-sanitizing-escaping/#escaping-securing-output
	// sanitize_email() -> https://developer.wordpress.org/reference/functions/sanitize_email/
	// sanitize_file_name()
	// sanitize_html_class()
	// urlencode_deep()
	// wp_redirect()
	// wp_safe_redirect()


	//
	// ********************
	// ********************
	// ********************
	// ********************
	// ********************

}



$wp_data_validation = new wp_data_validation;


$title = '<div>hello</div>';
$variable = "Hi";
$url = 'https://www.google.de/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png';
$fname = ( isset( $_POST['fname'] ) ) ? $_POST['fname'] : '';
$text = '<div>hello</div><script>alert("I am an alert box!");</script>'


?>



<h4><?php echo $wp_data_validation->esc_html( $title ); ?></h4>

<img src="<?php echo $wp_data_validation->esc_url( $url ); ?>" />

<a href="#" onclick="alert( '<?php echo $wp_data_validation->esc_js( $variable ); ?>' );">Click me</a>

<input type="text" name="fname" value="<?php echo $wp_data_validation->esc_attr( $fname ); ?>">

<textarea><?php echo $wp_data_validation->esc_textarea( $text ); ?></textarea>
