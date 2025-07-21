rule ZaCo_PHP_WebShell_MCP {
   meta:
      author = "Malware Analyst"
      date = "2025-07-19"
      description = "Detects ZaCo PHP web shell variants"
      family = "WebShell"
      platform = "PHP"
      severity = "High"
      reference = "ZaCo PHP web shell analysis"
   strings:
      // Author signatures and identifying comments
      $author1 = "Small PHP Web Shell By ZaCo" nocase
      $author2 = "KingDefacer" nocase
      $author3 = "kingdefacer@msn.com" nocase
      $author4 = "ZaCo MySQL Dumper" nocase

      // HTML title pattern specific to this shell
      $title = "<title>Small Web Shell By Zaco" nocase

      // Unique function names specific to this web shell
      $func1 = "function magic_q("
      $func2 = "function get_perms("

      // Distinctive PHP patterns and functionality
      $php1 = "get_magic_quotes_gpc()"
      $php2 = "@set_time_limit(0);"
      $php3 = "posix_getpwuid(@fileowner("
      $php4 = "$page!='cmd'&&$page!='mysql'&&$page!='eval'"

      // MySQL dumper specific strings
      $mysql1 = "#ZaCo MySQL Dumper"
      $mysql2 = "mysql_connect($host,$user,$passwd)"
      $mysql3 = "show columns from"

      // File operations and web shell capabilities
      $capability1 = "basename(__FILE__)"
      $capability2 = "$_FILES[\"filename\"][\"tmp_name\"]"
      $capability3 = "Content-Disposition: attachment"

      // Specific HTML form elements
      $form1 = "<input name='page' value='cmd' type=hidden>"
      $form2 = "<input name='page' value='mysql' type=hidden>"
      $form3 = "<input name='page' value='eval' type=hidden>"

      // Distinctive variable patterns
      $var1 = "$e_work_dir=htmlspecialchars($work_dir"
      $var2 = "$winda=strpos(strtolower(php_uname()),'wind')"
   condition:
      // File must be a PHP file or have PHP opening tag
      (uint16(0) == 0x3f3c or $php2) and

      // Must have author signatures (at least one)
      (any of ($author*)) and

      // Must have distinctive function names (high confidence indicators)
      ($func1 and $func2) and

      // Must have web shell capabilities indicators
      (2 of ($capability*)) and

      // Must have page navigation structure
      (2 of ($form*)) and

      // Additional distinctive PHP and MySQL features
      (any of ($mysql*, $var*, $php1, $php3, $php4, $title)) and

      // File size reasonable for a web shell (not too small, not too large)
      filesize < 50KB and filesize > 5KB
}

rule webshell_60a62ddb_wordpress_fake_MCP {
   meta:
      author = "YARA Rule Generator"
      date = "2025-07-19"
      description = "Detects sophisticated webshell masquerading as WordPress core file"
      sha256 = "60a62ddb7cd9dc7f1f69c12e6e2fec741791a9df415c1bd4dcf00630c3e18b0f"
   strings:
      $wp_masq = "Sets up the default filters and actions for most"
      $strrev_b64 = "strrev('46esab')"
      $strrev_gz = "strrev('etalfnizg')"
      $newname = "if(isset($_POST['newname']))"
      $marker = "echo 'xXsUIssAZ:'"
   condition:
      filesize < 50KB and
      $wp_masq and $strrev_b64 and $strrev_gz and
      $newname and $marker
}

rule webshell_404super_php_MCP {
   meta:
      author = "YARA Rule Generator"
      date = "2025-07-19"
      description = "Detects 404super.php webshell with pack obfuscation"
      sha256 = "4b60f56db6446f7f775346a754402cdfc632118ff578f50e297f4a7b5a5816a2"
   strings:
      $pack_func = "pack('c*', 0x70, 0x61, 99, 107)"
      $globals_var = "$GLOBALS = array("
      $session_var = "!isset($_SESSION['t'])"
      $obfus_func = "call_user_func"
   condition:
      filesize < 5KB and
      $pack_func and $globals_var and
      ($session_var or $obfus_func)
}

rule NCC_Shell_Webshell_MCP {
   strings:
      $a = ".:NCC:. Shell v"
      $b = "Hacked by Silver"
      $c = "Shell_Exec"
   condition:
      $a and $b and $c
}

rule PHP_Webshell_Obfuscated_Payload_MCP {
   meta:
      description = "Detects PHP webshell with obfuscated payload and malicious JavaScript redirects"
      author = "Malware Analyst"
      date = "2025-07-19"
      reference = "7e39e13ceb3967cbc3be73e6ba836da07737680f593e82b44f72fd168ca347ce.php"
      severity = "high"
      malware_family = "webshell"
   strings:
      // PHP obfuscation patterns
      $php1 = "strr'.'ev" ascii
      $php2 = "base6'.'4'.'_d'.'ec'.'ode" ascii
      $php3 = "st'.'r'.'_r'.'ot1'.'3" ascii
      $php4 = "gzuncompre'.'ss" ascii

      // Suspicious eval chain
      $eval_chain = "eval($CJydQ($FAoMx($AKkiE($uYXiL(" ascii

      // JavaScript obfuscation patterns
      $js1 = "function _0x" ascii
      $js2 = "mobileCheck" ascii
      $js3 = "localStorage" ascii

      // Encoded domain patterns (common in malicious redirects)
      $domain1 = "\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f" ascii  // http://
      $domain2 = "\\x6f\\x6c\\x61\\x6d\\x65\\x2e\\x6c\\x69\\x76\\x65" ascii  // olame.live

      // Database interaction with user input (SQLi potential)
      $sqli = "mysql_query(\"DELETE FROM cadastros WHERE id='$" ascii

      // Error suppression (common in webshells)
      $suppress = "error_reporting(0)" ascii
      $log_null = "ini_set('error_log', NULL)" ascii

      // Session start (common webshell pattern)
      $session = "session_start()" ascii
   condition:
      uint16(0) == 0x3f3c and
      filesize < 50KB and
      (
         // PHP obfuscation combo
         (3 of ($php*) and $eval_chain) or

         // JavaScript redirection combo
         (2 of ($js*) and 2 of ($domain*)) or

         // Database + error suppression combo
         ($sqli and ($suppress or $log_null)) or

         // Mixed PHP/JS webshell pattern
         ($session and 2 of ($php*) and $js1)
      )
}

rule BLaSTER_Webshell_MCP {
   meta:
      description = "Detects BLaSTER PHP webshell and similar variants"
      author = "Generated by YARA rule creator"
      date = "2025-07-19"
      sha256 = "ffdf48ce2a39df4b64c6a0f363b591b161ae93525849c7fd00169c0c6b17c126"
      category = "webshell"
      family = "BLaSTER"
      threat_level = "high"
   strings:
      // Unique author/group identifiers
      $author1 = "Kodlama by BLaSTER" nocase
      $author2 = "TurkGuvenligi" nocase
      $author3 = "priv8coder@gmail.com" nocase

      // Distinctive functionality strings
      $func1 = "Server listeleyici" nocase
      $func2 = "Tablo bulucu" nocase
      $func3 = "SQL injection tarama" nocase
      $func4 = "Joomla token" nocase
      $func5 = "Fake Mail" nocase
      $func6 = "Hex çevirici" nocase

      // Specific technical patterns
      $curl1 = "http://www.guerrilladns.com/index.php"
      $curl2 = "CURLOPT_POSTFIELDS"
      $pattern1 = "cannot find the input table or query"
      $pattern2 = "/index.php?option=com_user&view=reset&layout=confirm"
      $pattern3 = "Unclosed" ascii
      $pattern4 = "JET Database" ascii

      // Default table names list (distinctive pattern)
      $tables = "admin\nadmins\nusers\nuyeler\nuye\nkullanici" nocase

      // Turkish strings that are distinctive
      $turkish1 = "sayfayi tekrar aç" nocase
      $turkish2 = "Taramaya basla" nocase
      $turkish3 = "Gönderen email" nocase

      // Suspicious combination patterns
      $exploit1 = "eregi('token',$al)" nocase
      $exploit2 = "bin2hex($hex)" nocase
   condition:
      filesize < 50KB
      and (
         // Strong author attribution (2+ matches)
         (
            ($author1 or $author2 or $author3)
            and 2 of ($func*)
         )
         or
         // Multiple functional capabilities
         (
            4 of ($func*)
            and ($curl1 or $curl2)
         )
         or
         // Technical pattern combination
         (
            $tables
            and 2 of ($pattern*)
            and ($exploit1 or $exploit2)
         )
         or
         // Turkish language + malicious patterns
         (
            2 of ($turkish*)
            and 2 of ($func*)
            and ($curl1 or $curl2)
         )
      )
}

rule MyShell_PHP_Webshell_MCP {
   meta:
      description = "Detects MyShell PHP webshell and variants"
      author = "Malware Analyst"
      date = "2025-07-18"
      severity = "high"
      category = "webshell"
   strings:
      $a = "MyShell 1.1.0 build" ascii
      $b = "MyShell" ascii
      $c = "Digitart Producciones" ascii
      $d = "$selfSecure" ascii
      $e = "$shellUser" ascii
      $f = "system($command" ascii
      $g = "exec($command" ascii
      $h = "$PHP_AUTH_USER" ascii
      $i = "WWW-Authenticate: Basic realm" ascii
      $j = "explode(\" \",$command)" ascii
      $k = "name=\"shell\"" ascii
      $l = "name=\"shellOut\"" ascii
      $m = "name=\"command\"" ascii
      $n = "$editMode" ascii
      $o = "_SERVER['HTTP_REFERER']" ascii
      $p = "mail($" ascii
   condition:
      uint16(0) == 0x3f3c and
      ($a or ($b and $c)) and
      ($f or $g) and
      $j and
      3 of ($d, $e, $h, $i, $n) and
      2 of ($k, $l, $m) and
      ($o or $p)
}

rule Laravel_Obfuscated_Webshell_MCP {
   meta:
      description = "Detects obfuscated webshell disguised as Laravel framework index file"
      author = "Malware Analyst"
      date = "2025-07-19"
      version = "1.0"
      hash = "d4a0f0b19b30d60c078424a9afd1fcc0ca22744f2b42c37ee7ac201d8d5d114a"
      category = "webshell"
      severity = "high"
   strings:
      // Core malicious indicators
      $obfuscated_include = "@include"
      $hex_comment = "4a664"

      // Octal-encoded path components
      $octal_home = "057hom"
      $octal_public = "165bli"
      $octal_html = "143_ht"
      $octal_ico = "151co"

      // Laravel camouflage strings
      $laravel_brand = "Laravel - A PHP Framework For Web Artisans"
      $laravel_start = "LARAVEL_START"
      $illuminate = "Illuminate"

      // Suspicious path patterns
      $tradrdv_path = "tradrdv"
      $autoload_path = "vendor/autoload.php"
   condition:
      // File must be PHP
      uint16(0) == 0x3c3f and

      // Must have core malicious elements
      $obfuscated_include and $hex_comment and

      // Must have octal obfuscation (at least 2 patterns)
      (#octal_home + #octal_public + #octal_html + #octal_ico) >= 2 and

      // Must have Laravel camouflage (at least 2 patterns)  
      (#laravel_brand + #laravel_start + #illuminate) >= 2 and

      // Must have suspicious paths
      $tradrdv_path and $autoload_path and

      // Reasonable file size
      filesize > 500 and filesize < 20000
}

/*
    YARA Rule for Obfuscated PHP Webshell Detection
    
    Description: Detects PHP webshells using nested obfuscation techniques
    with base64 encoding, gzip compression, and htmlspecialchars_decode
    
    Author: Malware Analyst
    Date: 2025-07-19
    
    This rule targets PHP files that use multiple layers of obfuscation
    commonly found in webshells and malicious PHP scripts.
*/

rule ObfuscatedPHP_Webshell_MCP {
   meta:
      description = "Detects obfuscated PHP webshells using nested decode functions"
      author = "Malware Analyst"
      date = "2025-07-19"
      version = "1.0"
      severity = "high"
      family = "webshell"
      hash = "b45fc7c8b72d4f712213bdcfbee13f76ffd05796a4435836ac8d941967b3ee1c"
   strings:
      // PHP opening tag
      $php_tag = "<?php"

      // Variable assignment patterns commonly used in obfuscated PHP
      $var_pattern1 = /\$[a-zA-Z][a-zA-Z0-9_]* = "[A-Za-z0-9+\/=]{50,200}"/

      // Nested function calls for deobfuscation
      $deobfuscate1 = "eval(htmlspecialchars_decode(gzinflate(base64_decode("
      $deobfuscate2 = "eval(gzinflate(base64_decode("
      $deobfuscate3 = "htmlspecialchars_decode(gzinflate(base64_decode("

      // Base64 patterns (long base64 strings) - more specific
      $base64_long = /[A-Za-z0-9+\/]{100,500}={0,2}/

      // Hex encoded characters in strings (obfuscation technique)
      $hex_chars = /\\x[0-9a-fA-F]{2}/

      // Suspicious variable names often used in webshells  
      $sus_vars = /\$[a-z]{3,4}[0-9]/

      // Short, cryptic variable assignments with limited length
      $short_vars = /\$[a-z]{1,3} = ".{20,100}"/
   condition:
      // Must be a PHP file
      $php_tag at 0 and

      // Must contain long base64 strings
      #base64_long >= 1 and

      // Must use nested deobfuscation functions
      any of ($deobfuscate*) and

      // Must have multiple obfuscation indicators
      (
         (#var_pattern1 >= 1) or
         (#hex_chars >= 3) or
         (#sus_vars >= 1) or
         (#short_vars >= 1)
      ) and

      // File size should be reasonable for a webshell (not too small, not too large)
      filesize < 50KB and filesize > 1KB
}

