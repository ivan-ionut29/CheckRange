<?php
/**
 * Copyright (c) 2016 Ivan Ionut <ivan.ionut7@gmail.com>
 *
 * @license GNU General Public License v2.0
 */

namespace CheckRange;

class Range
{
    /** 
     * @var string the ip
     */
    private $ip;

    /**
     * @var string the cidr
     */
    private $cidr;

    /**
     * @var string the left ip of a range eg. 1.2.3.4 from "1.2.3.4-1.2.3.6"
     */
    private $leftRange;

    /**
     * @var string the right ip of a range eg. 1.2.3.6 from "1.2.3.4-1.2.3.6"
     */
    private $rightRange;

    /**
     * @var string the long formatted of $leftRange
     */
    private $longLeftRange;

    /**
     * @var string the long formatted of $rightRange
     */
    private $longRightRange;

    /**
     * @var string[] with ranges 
     */
    private $ranges = [];    

    public function __construct($input)
    {
        $this->formatInput($input); 
    }
    
    /** 
     * @param string $ip
     */
    public function validateIp($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            throw new \Exception("Invalid ip: $ip");
	}        
    }

    /**
     * @param string $cidr
     */
    public function validateCidr($cidr)
    {      
        if ($cidr <=0 || $cidr >= 32) {
            throw new \Exception("Invalid cidr: " . $this->ip . "/" . $this->cidr);
        }
    }

    /**
     * @param string $longLeftRange
     * @param string $longRightRange
     */	    
    public function validateLongRanges($longLeftRange, $longRightRange)
    {
        if (1 === gmp_cmp($longLeftRange, $longRightRange)) {
            throw new \Exception("Invalid range " . $leftRange . "-" . $rightRange);
        }
    }

    /**
     * @param string $ip
     * @param string long - long integer version in string format
     */
    public function ipToLong($ip, $long)
    {
        $this->$long = sprintf("%u", ip2long($this->$ip)); 
    }

    /** 
     * 
     */    
    public function formatRange()
    {
        $this->ipToLong('leftRange', 'longLeftRange');
	$this->ipToLong('rightRange', 'longRightRange');	    
        $this->validateLongRanges($this->longLeftRange, $this->longRightRange);    
    }

    /** 
     * 
     */
    public function addRangeToArray($left, $right) 
    {       
        $this->ranges[] = array($this->$left, $this->$right); 
    }

    /** 
     * 
     */	     
    public function  extractRange($range, $left, $right)
    {
        $ranges = explode("-", $range);
	$this->$left  = trim($ranges[0]);   
	$this->$right = trim($ranges[1]);    
    }

    /** 
     * 
     */	    
    public function extractIpCidr($class)
    {
        $elements   = explode("/", $class);
        $this->ip   = trim($elements[0]);
        $this->cidr = trim($elements[1]);
    }

    /** 
     * @param string $ip
     * @param int $mask
     */
    public function cidrToLongRange($ip, $mask)
    {
        // complementary mask  
        $cmask = 32 - $mask;
        
        // binary complementary mask transformed to long int   
        $ones = gmp_strval(gmp_sub(gmp_strval(gmp_pow("2", $cmask)), "1"));
	
        // long int mask 
	$mask = gmp_strval(gmp_mul(gmp_strval(gmp_pow("2", $cmask)),
			           gmp_strval(gmp_sub(
                                   gmp_strval(gmp_pow("2", $mask)), "1"))));
	  	
	// string subnet 
	$this->longLeftRange = gmp_strval(gmp_and(sprintf("%u", ip2long($ip)), $mask), 10);

        // string broadcast ip 
	$this->longRightRange = gmp_strval(gmp_add($this->longLeftRange, $ones));
    }  

    /** 
     * @param string $input
     */	    
    public function formatInput($input) 
    {
        if (is_string($input)) {
	    if (preg_match("#-#", $input)) {
	        $this->extractRange($input, "leftRange", "rightRange");
		$this->validateIp($this->leftRange);
		$this->validateIp($this->rightRange);
		$this->formatRange();            
	    } elseif (preg_match("#/#", $input)) {
	       	$this->extractIpCidr($input);
		$this->validateIp($this->ip);
		$this->validateCidr((int)$this->cidr); 		    
		$this->cidrToLongRange($this->ip, (int)$this->cidr);
            } else {
		$this->validateIp($input);
		$this->leftRange = $this->rightRange = $this->ip = $input;
		$this->formatRange(); 
	    }
            $this->addRangeToArray('longLeftRange', 'longRightRange');
		
        } else {
            foreach($input as $element) {
                $this->formatInput($element);
	    }
	} 
    }

    /** 
     * @return array
     */	   
    public function getRanges()
    {
        return $this->ranges;
    }
}

