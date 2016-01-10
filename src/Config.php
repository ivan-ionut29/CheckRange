<?php
/**
 * Copyright (c) 2016 Ivan Ionut <ivan.ionut7@gmail.com>
 *
 * @license GNU General Public License v2.0
 */

namespace CheckRange;

class Config
{
    /**
     * string filename, location where ranges will be temporarily saved and modified
     */
    private $fileSession;
    
    /**
     * string xml filename, location where each ip of every range will be saved with
     * its number of lists    
     */
    private $fileSavedData;

    public function __construct($fileSavedData="", $fileSession="")
    {
        $this->fileSavedData = $fileSavedData;
        $this->fileSession   = $fileSession;
        $this->check_gmp();        
    }

    /**
     *
     */
    public function check_gmp()
    {
        if (!function_exists('gmp_strval')) {
            throw new \Exception("Gmp extension must be installed/enabled"); 
        }
    }
   
    /**
     * @param string filename $file
     */ 
    public function setFileSession($file)
    {
        $this->fileSession = $file;
    }
    
    /**
     * @param string filename $file
     */
    public function setFileData($file)
    {
        $this->fileSavedData = $file;
    }
    
    /**
     * @param string filename $file
     * @param string $errorMessage
     */
    public function checkFile($file, $errorMessage)
    {
        if (!file_exists($file)) {
            throw new \Exception($errorMessage);    
        }
      
        if (!is_writable($file)) {
            throw new \Exception($errorMessage);
        }
    }
    
    /**
     * 
     */
    public function  checkFileSession()
    {
        $this->checkFile($this->fileSession,
                         "Session file does not exist or is not writable");    
    }
    
    /**
     * 
     */   
    public function checkFileData()
    {
        $this->checkFile($this->fileSavedData,
                         "Data file does not exist or is not writable ");
    }
    /**
     * @return string|null
     */ 
    public function getFileSession()
    {
        return $this->fileSession;
    }

    /**
     * @return string|null
     */ 
    public function getFileData()
    {
        return $this->fileSavedData;
    }   
}
