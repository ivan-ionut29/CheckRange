<?php
/**
 * Copyright (c) 2016 Ivan Ionut <ivan.ionut7@gmail.com>
 *
 * @license GNU General Public License v2.0
 */

namespace CheckRange;

class CheckRange
{
    /**
     * @var string[] with ranges 
     */
    private $ranges = [];

    /** 
     * @var string the ip
     */
    private $ip;

    /** 
     * @var int the number of lists
     */
    private $listsCount = 0;
    
    /** 
     * @var string the content of every blacklist site
     */
    private $content = null;

    /** 
     * @var object of Config class
     */
    private $config; 

    /** 
     * @var string[] with rules
     */
    private $rules = [
       
        [ "link" => "http://www.anti-spam.org.cn/search",
          "pattern" => '#IP status</span>[\t\s]*<span>[\t\s]*listed#', 
          "getQuery" => "/", "postQuery" => "", "extraParam" => "" ],
        
        [ "link" => "http://api.blocklist.de/api.php",
          "pattern" => "#(attacks: [1-9]+[0-9]*)|(reports: [1-9]+[0-9]*)#",
          "getQuery" => "?ip=", "postQuery" => "", "extraParam" => "&start=1"],
        
        [ "link" => "http://antispam.imp.ch/spamlist", "pattern" => "",
          "getQuery" => "", "postQuery" => "", "extraParam" => "" ],
               
        [ "link" => "http://drmx.org/index.php",
          "pattern" => "#listed in DrMX blacklist#",  
          "getQuery" => "?id", "postQuery" => "", "extraParam" => ""], 

        [ "link" => "http://dronebl.org/lookup", 
          "pattern" => "#There have been listings for the host#",
          "getQuery" => "?ip=", "postQuery" => "", "extraParam" => ""], 

         [ "link" => "http://www.spamsources.fabel.dk/lookup",  
           "pattern" => "#<i>is listed in spamsources.fabel.dk</i>#",
           "getQuery" => "?ip=", "postQuery" => "", "extraParam" => ""],

         [ "link" => "http://dnsbl.inps.de/query.cgi",
           "pattern" => "#DNS status DNSBL</td><td style='color:red' nowrap>listed</td>#",
           "getQuery" => "?action=check&lang=en&ip=", "postQuery" => "",
           "extraParam" => ""],

         [ "link" => "http://blacklist.jippg.org/cgi-local/query.cgi",
            "pattern" => "#is currently on mail-abuse.blacklist.jippg.org#",
            "getQuery" => "?query=", "postQuery" => "", "extraParam" => ""],

         [ "link" => "https://bl.konstant.no/search.php",
           "pattern" => "#<b>is blacklisted</b>#",
           "getQuery" => "?address=", "postQuery" => "", "extraParam" => ""],
         
         [ "link" => "http://blacklist.lashback.com/",
           "pattern" => "#is listed in UBL#",
           "getQuery" => "?ipAddress=", "postQuery" => "", "extraParam" => ""],

         [ "link" => "http://mailblacklist.com/lookup.php",
           "pattern" => "#Your IP Address is listed in our Database#",
           "getQuery" => "?ip=", "postQuery" => "", "extraParam" => ""],
           
         [ "link" => "https://www.megarbl.net/blocking_list.php",
           "pattern" => "#is listed in the RBL#",
           "getQuery" => "?ip=", "postQuery" => "", "extraParam" => ""],    
         
         [ "link" => "http://0spam.fusionzero.com/check/",
           "pattern" => "#<font color=red>Listed!#",
           "getQuery" => "?ipaddr=", "postQuery" => "", "extraParam" => ""],
    
         [ "link" => "http://psbl.org/listing",
           "pattern" => "#Currently listed in PSBL\?[\t\s]*Yes#",
           "getQuery" => "?ip=", "postQuery" => "", "extraParam" => ""],
 
         [ "link" => "http://www.spamrats.com/lookup.php",
           "pattern" => "#<strong>RATS-Spam</strong>[\t\s]*-[\t\s]*On the list#",
           "getQuery" => "?ip=", "postQuery" => "", "extraParam" => ""],
         
         [ "link" => "http://psky.me/check/",
           "pattern" => "#Poor Reputation#",
           "getQuery" => "", "postQuery" => "ip", "extraParam" => ""],
 
    ];

    /** 
     * @var string[] with rules from blacklistalert.org
     */
    public $rulesListAlert = [
        "ips.backscatterer.org", "b.barracudacentral.org", "cbl.abuseat.org",
        "tor.dan.me.uk", "rbl.efnet.org", "spamguard.leadmon.net", "tor.dnsbl.sectoor.de",
        "dnsbl.sorbs.net", "bl.spamcannibal.org", "bl.spameatingmonkey.net",
        "bl.spamcop.net", "zen.spamhaus.org", "dnsbl-1.uceprotect.net", "multi.uribl.com",
        "dnsbl.justspam.org", "dnsbl.inps.de" 
    ];
      
    public function __construct($input)
    {
        $this->config = new Config;                
        $this->ranges = (new Range($input))->getRanges();
    }
    
    /**
     *
     */
    public function run()
    {
        $this->config->checkFileSession(); 
        $this->config->checkFileData();      
        $this->loadSession();        
        array_walk($this->rulesListAlert, array($this, 'formatListAlert'));
        array_map(array($this, 'iterateRanges'), $this->ranges);         
    }

    /**
     * On each iteration of the while loop:
     *    - the left range of the first range is: 
     *          - assigned to $this->ip (in dotted format) 
     *          - incremented until it is equal to righ range and then
     *          the while loop breaks
     *    - $this->ip is used in formatRule method and saveToXml
     *    - a session is saved
     * After while breaks the first range is removed from $this->ranges 
     * and a session is saved again.    
     */ 
    public function iterateRanges()
    {
        while(true) {
            $this->ip = long2ip($this->ranges[0][0]);
            array_map(array($this, 'iterateRules'), $this->rules);
            array_map(array($this, 'iterateRulesListAlert'), $this->rulesListAlert); 
            $this->saveToXml($this->ip, $this->listsCount);
            $this->resetToDefaults(); 

            if (0 === gmp_cmp($this->ranges[0][0], $this->ranges[0][1])) {                                  break;
            }
            $this->ranges[0][0] = gmp_strval(gmp_add($this->ranges[0][0], "1"));
            $this->saveSession();        
        }
        array_shift($this->ranges);
        $this->saveSession();
    }

    /**
     * @param array $rule
     */
    public function iterateRules($rule)
    {
        $rule = $this->formatRule($rule);
        $url = $rule['link'] . $rule['getQuery'] . $rule['extraParam'];
        if (preg_match_all($rule['pattern'], $this->getContent($url, $rule['postQuery']))) {
            $this->listsCount++;
        } 
    }
 
    /**
     * @param array $rule
     */
    public function iterateRulesListAlert($rule)
    {
        $rule = $this->formatRule($rule);
        if (is_null($this->content)) {
            $this->content = $this->getContent($rule['link'], $rule['postQuery']);
        }

        if (preg_match_all($rule['pattern'], $this->content)) {
            $this->listsCount++;
        }
    } 

    /**
     * @param array $rule
     */            
    public function formatListAlert(&$rule)
    {
        $rule = [ "link" => "http://www.blacklistalert.org",
                  "pattern" => "#{$rule}[\t\s]*<font color=red><em><b>Listed!#",
                  "getQuery" => "", "postQuery" => "q", "extraParam" => ""];    
    }

    /**
     * It formats elements of array $rule for get/post query
     * and for a particular where patern element is empty
     * (where blacklist sites are like antispam.imp.ch/spamlist)
     *
     * @param  array $rule
     * @return array
     */
    public function formatRule($rule) 
    {
        if ($rule['getQuery']!=="") {
            $rule['getQuery'] .= $this->ip;
        } else if ($rule['pattern'] === "") {
            $rule['pattern'] = "#[^0-9]" . $this->escapedIP($this->ip) . "[^0-9]#";
        } else {
            $rule['postQuery'] = [ $rule['postQuery'] => $this->ip ];
        }
        return $rule;
    }
    
    /**
     * @param string $Url
     * @param array $post
     * @return string Site content|false On failure 
     */
    public function getContent($Url, $post=[])
    {     
        if (!function_exists('curl_init')){
            die("CURL is not installed");
	} 
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $Url);

        if (!empty($post)) {
 	    curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
        }
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_VERBOSE, 0);
	$output = curl_exec($ch);
	curl_close($ch);
	return $output;       
    }

    /**
     * 
     */	    
    public function saveSession()
    {
        $str = "";
        foreach($this->ranges as $range) {
            $str.="{$range[0]} {$range[1]}\n";
        }
        $this->writeNewContent($this->config->getFileSession(), $str);   
    }
     
    /**
     * @param string $file
     * @param string $content
     */   
    public function writeNewContent($file, $content) 
    {
        $fp = fopen($file, "w");
        if (flock($fp, LOCK_EX)) {
            fwrite($fp, $content);
            flock($fp, LOCK_UN);
        }
        fclose($fp); 
    }

    /**
     * @param string $value
     * @param int $atribute 
     */
    public function saveToXml($value, $atribute)
    {
        $xml = simplexml_load_file($this->config->getFileData());
        $xml->addChild("ip", $value)->addAttribute("listed", $atribute);
        $this->writeNewContent($this->config->getFileData(), $xml->saveXML());
    }
    
    /**
     *
     */
    public function loadSession()
    {
        $temp_array = [];
        $lines = file($this->config->getFileSession(), FILE_SKIP_EMPTY_LINES);
        foreach($lines as $line) {
            if (!preg_match("/[0-9]/", $line)) {
                continue;
            }   
            $temp_array[] = explode(" ", trim($line));
        }

        if (!empty($temp_array)) {
            $this->ranges = $temp_array;
        }
    }
   
    /**
     * @param string $list 
     */ 
    public function loadList($list)
    {
        $this->config->checkFile($list, "List file does not exist or is not writable");
        $temp_array = [];
        $lines = file($list, FILE_SKIP_EMPTY_LINES);
        foreach($lines as $line) {
            if (!preg_match("/[0-9]/", $line)) {
                continue;
            }   
            $temp_array[] = trim($line); 
        }
        if (!empty($temp_array)) {
            $this->ranges = (new Range($temp_array))->getRanges();
        }
    }
    
    /**
     * @param string $ip
     * @return string formated ip eg.  xxx\.yyy\.www\.zzz
     */ 
    public function escapedIP($ip)
    {
        return str_replace(".", "\.", $ip);
    }
    
    /**  
     * 
     */
    public function resetToDefaults()
    {
        $this->content=null;
        $this->listsCount=0;  
    }
    
    /**  
     * @param string $fileSession 
     */
    public function setFileSession($fileSession)
    {
        $this->config->setFileSession($fileSession);
    }
   
    /**  
     * @param string $fileData
     */
    public function setFileData($fileData)
    {
        $this->config->setFileData($fileData); 
    }
}


