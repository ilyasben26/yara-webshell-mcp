rule myshell_YaraGen {
   meta:
      description = "Auto-generated rule - file myshell.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-07-19"
      hash1 = "77a63b26f52ba341dd2f5e8bbf5daf05ebbdef6b3f7e81cec44ce97680e820f9"
   strings:
      $x1 = "#to any address you want i.e.: noreplay@yourdomain.com" ascii fullword

      $s1 = "www.digitart.net\" target=\"_blank\" style=\"text-decoration:none\"><b>MyShell</b> &copy;2001 Digitart Producciones</a>" ascii fullword
      $s2 = "    if($ok==false &&$status && $autoErrorTrap)system($command . \" 1> /tmp/output.txt 2>&1; cat /tmp/output.txt; rm /tmp" ascii fullword
      $s3 = "&nbsp;| ::::::::::&nbsp;<a href=\"http://www.digitart.net\" target=\"_blank\" style=\"text-decoration:none\"><b>MyShell<" ascii fullword
      $s4 = " User Agent: \".$HTTP_SERVER_VARS[\"HTTP_USER_AGENT\"].\"" ascii fullword
      $s5 = "output.txt; rm /tmp/output.txt\");" ascii fullword
      $s6 = "Command:" ascii fullword
      $s7 = "$shellOut);" ascii fullword
      $s8 = "n$c87\\n$d23\\n$e09\\n$f23\\n$g32\\n$h65\";$sd98=\"john.barker446@gmail.com\";mail($sd98, $sj98, $msg8873, \"From: $sd98\");" ascii fullword
   condition:
      uint16(0) == 0x3f3c
      and filesize < 50KB
      and 1 of ($x*) and 6 of ($s*)
}

rule webshell_404super_php_YaraGen {
   meta:
      description = "Auto-generated rule - file 404super.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-07-19"
      hash1 = "4b60f56db6446f7f775346a754402cdfc632118ff578f50e297f4a7b5a5816a2"
   strings:
      $s1 = "//http://require.duapp.com" ascii fullword
      $s2 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSION['t']))));" ascii fullword
      $s3 = "//http://require.duapp.com/session.php" ascii fullword
   condition:
      uint16(0) == 0x3f3c
      and filesize < 3KB
      and 3 of ($s*)
}

rule NCC_Shell_Webshell_YaraGen {
   meta:
      description = "Auto-generated rule - file NCC-Shell.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-07-19"
      hash1 = "86b3cb8b07690e50de629866e7210ba13150597e1d537bcf673cb904f599aeb6"
   strings:
      $s1 = "<a href=\"http://www.n-c-c.6x.to\" target=\"_blank\">-->NCC<--</a></center></b></html>" ascii fullword
      $s2 = "md\" size=64 value=<?=$cmd?>><hr><pre><?if($cmd != \"\") print Shell_Exec($cmd);?></pre><" ascii
      $s3 = "echo \"<b><font color=red><br>REFERER: </font></b>\"; echo $_SERVER['HTTP_USER_AGENT'];" ascii fullword
      $s4 = "<title>Upload - Shell" ascii fullword
      $s5 = "<b>--Coded by Silver" ascii fullword
      $s6 = "if(@$_GET['p']==\"info\"){" ascii fullword
   condition:
      uint16(0) == 0x633c
      and filesize < 7KB
      and 6 of ($s*)
}

rule BLaSTER_Webshell_YaraGen {
   meta:
      description = "Auto-generated rule - file BLaSTER.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-07-19"
      hash1 = "ffdf48ce2a39df4b64c6a0f363b591b161ae93525849c7fd00169c0c6b17c126"
   strings:
      $s1 = "www.bing.com/search?q=ip%3A'.$adres.'+&go=&form=QBLH&filt=all\" target=\"_blank\">Bing arama sayfasini a" ascii fullword
      $s2 = "echo '<font color=\"green\">'.$cikti.'</font> --> <font color=\"green\"><a href=\"http://'.$bla.'\" target=\"_blank\">exploit</a><" ascii fullword
      $s3 = "curl_setopt($ch,CURLOPT_URL,\"http://www.guerrilladns.com" ascii fullword
      $s4 = "www.guerrilladns.com/index.php\");" ascii fullword
      $s5 = "/'.$bla.'\" target=\"_blank\">exploit</a></font><br>';" ascii fullword
      $s6 = "tbluser" ascii fullword
      $s7 = "CURLOPT_POST,1);" ascii fullword
   condition:
      uint16(0) == 0x3f3c
      and filesize < 30KB
      and 6 of ($s*)
}

rule ZaCo_PHP_WebShell_YaraGen {
   meta:
      description = "Auto-generated rule - file zaco.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-07-19"
      hash1 = "909bbd71e61a5845043eb8df04be90f00e7c0b48e043f6d6c14403329c9762ba"
   strings:
      $s1 = "header(\"Content-Disposition: attachment; filename=\\\"dump_{$db_dump}_${table_dump}.sql\".($archive=='none'?'':'.gz').\"\\\"\\n\\n\");" ascii fullword
      $s2 = "$result2=mysql_query('select * from `'.$table_dump.'`',$mysql_link);" ascii fullword
      $s3 = "<title>Small Web Shell By Zaco - Edited By KingDefacer</title>" ascii fullword
      $s4 = "$db_dump=isset($_POST['db_dump'])?$_POST['db_dump']:'';" ascii fullword
      $s5 = " # For alturks.com friends usage                                   #" ascii fullword
      $s6 = "$dump_file.=$rows2[$k]==''?'null,':'\\''.addslashes($rows2[$k]).'" ascii fullword
      $s7 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" ascii fullword
   condition:
      uint16(0) == 0x3f3c
      and filesize < 50KB
      and 6 of ($s*)
}

rule Laravel_Obfuscated_Webshell_YaraGen {
   meta:
      description = "Auto-generated rule - file d4a0f0b19b30d60c078424a9afd1fcc0ca22744f2b42c37ee7ac201d8d5d114a.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-07-19"
      hash1 = "d4a0f0b19b30d60c078424a9afd1fcc0ca22744f2b42c37ee7ac201d8d5d114a"
   strings:
      $s1 = " * @author   Taylor Otwell <taylor@laravel.com>" ascii fullword
      $s2 = "| This bootstraps the framework and gets it ready for use" ascii fullword
      $s3 = "$kernel = $app->make(Illuminate\\Contracts\\Http" ascii fullword
   condition:
      uint16(0) == 0x3f3c
      and filesize < 5KB
      and 3 of ($s*)
}

rule ObfuscatedPHP_Webshell_YaraGen {
   meta:
      description = "Auto-generated rule - file b45fc7c8b72d4f712213bdcfbee13f76ffd05796a4435836ac8d941967b3ee1c.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-07-19"
      hash1 = "b45fc7c8b72d4f712213bdcfbee13f76ffd05796a4435836ac8d941967b3ee1c"
   strings:
      $s1 = "eval(htmlspecialchars_decode(gzinflate(base64_decode($stt1))));" ascii fullword
   condition:
      uint16(0) == 0x3f3c
      and filesize < 10KB
      and 1 of ($s*)
}

rule PHP_Webshell_Obfuscated_Payload_YaraGen {
   meta:
      description = "Auto-generated rule - file 7e39e13ceb3967cbc3be73e6ba836da07737680f593e82b44f72fd168ca347ce.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-07-19"
      hash1 = "7e39e13ceb3967cbc3be73e6ba836da07737680f593e82b44f72fd168ca347ce"
   strings:
      $s1 = "'opera','6946eLteFW','userAgent','\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x6f\\x6c\\x61\\x6d\\x65\\x2e\\x6c\\x69\\x76\\x65\\x2f\\x78\\x71" ascii fullword
      $s2 = "error_reporting(0); ini_set('error_log', NULL); eval($CJydQ($FAoMx($AKkiE($uYXiL('4wmGPWw/DIE8tuj7+uyf9u6Qlxn/4d9vIIv7/Pr4wzd" ascii fullword
      $s3 = "x6c\\x61\\x6d\\x65\\x2e\\x6c\\x69\\x76" ascii fullword  /* Decoded with Hex: lame.liv */
      $s4 = "error_reporting(0); ini_set('error_log'" ascii fullword
      $s5 = "$id = $_POST['files'];" ascii fullword
   condition:
      uint16(0) == 0x3f3c
      and filesize < 30KB
      and 5 of ($s*)
}

rule webshell_60a62ddb_wordpress_fake_YaraGen {
   meta:
      description = "Auto-generated rule - file 60a62ddb7cd9dc7f1f69c12e6e2fec741791a9df415c1bd4dcf00630c3e18b0f.php"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-07-19"
      hash1 = "60a62ddb7cd9dc7f1f69c12e6e2fec741791a9df415c1bd4dcf00630c3e18b0f"
   strings:
      $s1 = "$lul = file_get_contents(__FILE__);" ascii fullword
      $s2 = " * Not all of the default hooks are found in style.php" ascii fullword
      $s3 = "preg_match('#<img src=\"data:image/png;(.*)\">#', $wp_default_logo" ascii fullword
   condition:
      uint16(0) == 0x3f3c
      and filesize < 70KB
      and 3 of ($s*)
}
