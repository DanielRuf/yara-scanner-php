<?php

/**
 * copyright 2022 Magos Securitas GmbH
 * website: https://magos-securitas.com/malware-scanner/
 * support: https://threema.id/74SF7MW6?text=
 * updates: https://magos-securitas.com/rss.xml
 * license: proprietary
 * 
 * any resale, rent and commercial redistribution of this code is prohibited
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

//declare(strict_types = 1);

// this version uses an associative array as hash map (the inodes are the keys) of files
// to prevent that the same files are archived multiple times
// but keep in mind that building the hash map might cost some memory

$version = '1.2.0-next';
$product = 'malware scanner';
$author = 'Magos Securitas GmbH (https://magos-securitas.com)';
$logo = <<<CODE
                                                                          
                       'cdOXWc              :WXOxc,                       
                   ;xKMMMMMMMM:...',,,,'...,WMMMMMMMXx:.                  
                 :WMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMl                 
                  kMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMO                  
                 .dMMMMMMMMMMMMMMNXXKKXXNMMMMMMMMMMMMMMx.                 
               :0MMMMMMMMMNOo:'.          .';lkNMMMMMMMMMK:               
             :XMMMMMMMWO:.                      .:kWMMMMMMMNc             
           'KMMMMMMM0:                              :OMMMMMMMX,           
    .KWKd:dMMMMMMMk.                                  .xWMMMMMMx:d0WX.    
   .NMMMMMMMMMMMO.         ..                           .kMMMMMMMMMMMW'   
  .NMMMMMMMMMMWc      ,xKkoclxKx;       :coO000000dc:.    :WMMMMMMMMMMN.  
  0MMMMMMMMMMN,     ;XMK.     .OMX:        .NMMMM'         'NMMMMMMMMMMK  
 oMMMMMMMMMMN.     lMMN.        KMMd        OMMMN           .NMMMMMMMMMMd 
 dXMMMMMMMMM:     ,MMMc         ;MMMl       OMMMN            ;MMMMMMMMMXx 
   .;WMMMMMK      KMMM.          NMMW.      OMMMN             0MMMMMM:.   
    'MMMMMMc     ;MMMK           kMMMo      OMMMN             :MMMMMM,    
    cMMMMMM'     dMMMO           oMMMO      OMMMN             .MMMMMMl    
    lMMMMMM.     kMMMk           oMMMK      OMMMN             .MMMMMMo    
    :MMMMMM'     dMMMk           oMMMO      OMMMN             .MMMMMMl    
    'MMMMMMc     ,MMMK           kMMMl      OMMMN             :MMMMMM,    
   .:WMMMMMK      0MMW.          XMMN.      OMMMN             0MMMMMMc.   
 xNMMMMMMMMMc     ,MMM:         ,MMMc       OMMMN            :MMMMMMMMMWO 
 lMMMMMMMMMMW,     lMMX         0MMd        OMMMN           .NMMMMMMMMMMo 
  0MMMMMMMMMMW;     ;XM0.      kMN:        .NMMMM,         ,WMMMMMMMMMMK  
  .XMMMMMMMMMMMo      ,x0koclx0x;       :coO000000dc:.    lWMMMMMMMMMMN.  
   .XMMMMMMMMMMM0'         ..                           .0MMMMMMMMMMMN.   
    .0NOo;oWMMMMMMO'                                  'OMMMMMMMd;lONK.    
           .0MMMMMMMKl.                            .c0MMMMMMMK'           
             ;KMMMMMMMM0l'                      .l0MMMMMMMMK:             
               ,OMMMMMMMMMW0dc,..        ..,cd0WMMMMMMMMMO;               
                 .oMMMMMMMMMMMMMMMWNNNNWMMMMMMMMMMMMMMMd.                 
                  OMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM0                  
                 :WMMMMMMMMMMMMWMMMMMMMMMMMWMMMMMMMMMMMWc                 
                   ,o0WMMMMMMW, ...''''... 'WMMMMMMW0d,                   
                       .:ok0X:              ,XKko:.                       
                                                                          
CODE;

// define constants
define('MEM_PEAK_STR', 'Mem peak usage');
define('EXIT_CODE_STR', 'exit code');
define('CMD_STR', 'command');
define('ABORT_EXIST_STR', 'does not exist. Aborting.');
define('ABORT_FILE_STR', 'is not a file. Aborting.');
define('ABORT_DIR_STR', 'is not a directory. Aborting.');
define('ABORT_READABLE_STR', 'is not readable. Aborting.');
define('ABORT_EXECUTABLE_STR', 'is not executable. Aborting.');
define('LAST_ERR_STR', 'last error');
define('RULES_FILE_STR', 'rules file');
define('EXCEPTION_STR', 'Exception');
define('PROGRESS_CHAR_STR', '.');
define('PHP_SAPI_CLI_STR', 'cli');
define('ARCHIVE_STR', 'archive');

// define constants depending on the environment (browser vs cli)
if (PHP_SAPI === PHP_SAPI_CLI_STR) {
    define('PHP_EOL_OUTPUT', PHP_EOL);
} else {
    define('PHP_EOL_OUTPUT', '<br/>');
    define('START', '<!DOCTYPE html><html>');
    define('END', '</html>');
}

/**
 * DEBUGGING
 */

// ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);
// ignore_user_abort(true);
// set_time_limit(0);
// ini_set('memory_limit', '32M');

/**
 * SETTINGS
 */

// change these paths

// path / command for yara, for example '/usr/local/bin/yara'
$yara_binary = './yara';

// path to scan
$scan_path = './wordpress';

// path to the rules file
$rules_file = '../yara-rules/rules.yarc';
// for testing
// $rules_file = './test/example-rule.yar';
// $rules_file = './test/example-rule.yarc';
// $rules_file = './test/example-rule.zip';

// delete extracted rules file afterwards if (encrypted) archive is used
$rules_file_zip_cleanup = false;

// generate file list for scanning only a list of files
$create_files_list = false;

// skip regeneration if files list file already exists
$use_existing_files_list = false;

// path to generated file list
$files_list = './scanner-all-files';

// list of excluded extensions from generated file list
$files_list_excluded_extensions = [
    'css',
    'eot',
    'gif',
    'jpeg',
    'jpg',
    'js',
    'png',
    'scss',
    'ttf',
    'woff2',
    'woff'
];

// set the options for the yara scan
$scan_options = [
    'C', // compiled rules // has to be disabled for testing
    'f', // fast mode
    // 'm', // print metadata, this is slow
    // 'S', // show stats
    // 'e', // show rule namespace
    // 'g', // show rule tags
];

// add recursive option if no precompiled file list is used
if (!$create_files_list) {
    array_push($scan_options, 'r'); // recursive
}

// enable to archive the found files
$archive_files = false;

// enable to encrypt / password protect the archive
// disabled by default as it slows down the archive process
// requires zip extension 1.14.0 and libzip 1.2.0 or newer
$archive_encrypt = false;

// alternatively use ZipArchive::EM_AES_256, faster may be better
$encryption_method = false;
if (defined('ZipArchive::EM_AES_128')) {
    $encryption_method = ZipArchive::EM_AES_128;
}

// set the password for the archive zip file
$zip_password = 'infected';

// set the password for the rules zip file
$rules_zip_password = 'infected';

// get current time
$time = time();

// set logfile name
$logfile = 'logfile_scan_' . $time . '.txt';

// set archive file name
$archivefile = 'archive_scan_' . $time . '.zip';

// set to true if output should be directly displayed / streamed
$realtime = true;

// yara >= 4.2.0: --skip-larger=<bytes>, 0 by default?

/**
 * STOP EDITING
 */

// realtime updates
if ($realtime) {
    // disable all flushing features and implicitely flush on every output
    if (function_exists('apache_setenv')) {
        apache_setenv('no-gzip', 1);
    }

    ini_set('zlib.output_compression', '0');
    ini_set('implicit_flush', '1');

    for ($level = 0; $level < ob_get_level(); $level++) {
        ob_end_flush();
    }

    if (PHP_MAJOR_VERSION === 8) {
        ob_implicit_flush(true);
    } else {
        ob_implicit_flush(1);
    }
}

// output start element in browser to prevent invalid html which might cause display issues
if (defined('START')) {
    echo START;
}

// output logo and license details
if (PHP_SAPI !== PHP_SAPI_CLI_STR) {
    echo '<!--';
}

echo $logo;

if (PHP_SAPI !== PHP_SAPI_CLI_STR) {
    echo '-->';
}

echo PHP_EOL . $product . ' v' . $version . ' by ' . $author . PHP_EOL_OUTPUT . PHP_EOL_OUTPUT;

$start = microtime(true);

// signature checks
if (!file_exists($rules_file)) {
    exit($rules_file . ' ' . ABORT_EXIST_STR . PHP_EOL_OUTPUT);
}

if (!is_file($rules_file)) {
    exit($rules_file . ' ' . ABORT_FILE_STR . PHP_EOL_OUTPUT);
}

if (!is_readable($rules_file)) {
    exit($rules_file . ' ' . ABORT_READABLE_STR . PHP_EOL_OUTPUT);
}

// yara binary checks
if (!file_exists($yara_binary)) {
    exit($yara_binary . ' ' . ABORT_EXIST_STR . PHP_EOL_OUTPUT);
}

if (!is_executable($yara_binary)) {
    exit($yara_binary . ' ' . ABORT_EXECUTABLE_STR . PHP_EOL_OUTPUT);
}

// scan path checks
if (!file_exists($scan_path)) {
    exit($scan_path . ' ' . ABORT_EXIST_STR . PHP_EOL_OUTPUT);
}

if (!is_dir($scan_path)) {
    exit($scan_path . ' ' . ABORT_DIR_STR . PHP_EOL_OUTPUT);
}

if (!is_readable($scan_path)) {
    exit($scan_path . ' ' . ABORT_READABLE_STR . PHP_EOL_OUTPUT);
}

// if the rules are zipped, try to unzip and decrypt them
if (substr( $rules_file, -4 ) === '.zip') {

    // check if AES 256 is supported
    if (!defined('ZipArchive::EM_AES_256')) {
        exit('Encrypted archives not supported. Please check the system requirements.' . PHP_EOL_OUTPUT);
    }

    // initialize zip archive
    $rules_zip = new ZipArchive;

    // define filename to find in the archive (should be the same)
    $rules_file_zip = basename($rules_file, '.zip');

    // try to open the zip file
    if ($rules_zip->open($rules_file) !== true) {
        exit('Failed reading rules zip.' . PHP_EOL_OUTPUT);
    }

    // check if the rules file exists
    if ($rules_zip->locateName($rules_file_zip) !== false) {

        // set password for decryption
        $rules_zip->setPassword($rules_zip_password);

        // set final path with the right extension
        $rules_file = str_replace('.zip', '', $rules_file);

        // extract the file
        $rules_zip->extractTo(dirname($rules_file));

        // close the zip archive
        $rules_zip->close();

        // the extracted file should be deleted afterwards
        $rules_file_zip_cleanup = true;
    }
}

// get the hash of the rules file
$rules_file_hash = hash_file('sha256', $rules_file);

// convert options to string
$scan_options = implode('', $scan_options);

// create logfile and use the generated handle
$logfile_handle = fopen($logfile, 'w');

// create temporary reference, needed for setups with a folder of rules
$rules_file_original = $rules_file;

// initialize exit code variable for later
$exit_code = null;

// initialize ctime and mtime variables
$matched_earliest_ctime = 0;
$matched_earliest_mtime = 0;

// get inodes
$logfile_stat = stat($logfile);
$logfile_inode = $logfile_stat['ino'];
$logfile_filename = basename($logfile);

$scanner_stat = stat(__FILE__);
$scanner_inode = $scanner_stat['ino'];
$scanner_filename = basename(__FILE__);

// set string to split lines by
$split_lines_by = ' ';
if (strpos($scan_options, 'm')) {
    $split_lines_by = '"] ';
}

// optional: read a folder of yar files to an array and convert it to a string
// $rules_file = implode(' ', glob('./source/**/*.{yar}', GLOB_BRACE));

// epic: fallbacks / system support
// todo: popen fallback(s)

// create commands for yara
$version_command = $yara_binary . ' --version 2>&1';
$scan_command = $yara_binary . ' -' . $scan_options . ' ' . $rules_file . ' ' . $scan_path . ' 2>&1';

// find all files that do not have the excluded extensions
function findFilesWithoutExcludedExtensions(
    $scan_path,
    $files_list_excluded_extensions,
    $logfile_inode,
    $scanner_inode
) {
    foreach (new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(
            $scan_path,
            RecursiveDirectoryIterator::SKIP_DOTS
        )
    ) as $file) {
        // get relevant file details
        $scan_path_name = $file->getPathname();
        $file_extension = $file->getExtension();
        $file_name = $file->getBasename();

        // get file inode
        $scan_path_stat = stat($scan_path_name);
        $scan_path_inode = $scan_path_stat['ino'];

        if (
            // skip files that have one of the excluded extensions
            (
                $file_name !== $file_extension && // not sure if this is needed
                in_array($file_extension, $files_list_excluded_extensions)
            ) ||
            // skip the logfile
            $scan_path_inode === $logfile_inode ||
            // skip the scanner file
            $scan_path_inode === $scanner_inode
        ) {
            continue;
        }

        // return the full file path
        yield $scan_path_name;
    }
}

// stream the output of an executed command with generators
function runCommand($command, &$exit_code)
{
    // try {
    //     //code...
    // } catch (Exception $e) {
    //     //echo $e->getMessage();
    // }
    $handle = popen($command, 'r'); // alternatively rb on Windows if needed

    // while ($handle && $command_output = fgets($handle)) { // alternative version
    while ($handle && !feof($handle)) {
        // alternatively trim only specific characters
        // yield trim(fgets($handle, "\n\r")
        $command_output = fgets($handle);

        if ($command_output) {
            yield trim($command_output);
        }
    }

    if ($handle) {
        $exit_code = pclose($handle);
    }
}

// log input to logfile and current stdout
function logLineToAll($logfile_handle, $text)
{
    echo $text . PHP_EOL_OUTPUT;
    fwrite($logfile_handle, $text . PHP_EOL);
    fflush($logfile_handle);
}

$shutdown = function() use(
    &$logfile_handle,
    &$logfile,
    &$start,
    &$end,
    &$matched_earliest_ctime,
    &$matched_earliest_mtime,
    &$archive_files,
    &$archive_created,
    &$archivefile,
    &$archive_zip,
    &$exit_code,
    &$rules_file_zip_cleanup,
    &$rules_file)
{
    fwrite($logfile_handle, PHP_EOL);
    fwrite($logfile_handle, 'earliest ctime: ' . $matched_earliest_ctime . PHP_EOL);
    fwrite($logfile_handle, 'earliest mtime: ' . $matched_earliest_mtime . PHP_EOL);
    fflush($logfile_handle);

    $zip_start = microtime(true);
    $zip_end = $zip_start;

    // output archive path and close the zip file
    if (
        $archive_files &&
        $archive_created
    ) {
        if (file_exists($archivefile)) {
            fwrite($logfile_handle, ARCHIVE_STR . ': ' . $archivefile . PHP_EOL);
        } else {
            fwrite($logfile_handle, ARCHIVE_STR . ': ' . $archivefile . ' not created' . PHP_EOL);
        }
        fflush($logfile_handle);
        if ($archive_zip) {
            $result = $archive_zip->close();
            $zip_end = microtime(true);
        }
    }

    // output exit code details
    if ($exit_code) {
        echo EXIT_CODE_STR . ': ' . $exit_code . PHP_EOL_OUTPUT;
    }

    // add scan end details
    logLineToAll($logfile_handle, '');
    logLineToAll($logfile_handle, 'Scan finished at ' . $end);

    // log last error
    $error = error_get_last();
    if (
        $error &&
        $error['type'] === E_ERROR
    ) {
        logLineToAll($logfile_handle, LAST_ERR_STR . ' (message): ' . $error['message']);
        logLineToAll($logfile_handle, LAST_ERR_STR . ' (type): ' . $error['type']);
        logLineToAll($logfile_handle, LAST_ERR_STR . ' (file): ' . $error['file']);
        logLineToAll($logfile_handle, LAST_ERR_STR . ' (line): ' . $error['line']);
    }

    // output log file name
    echo 'Logfile: ' . $logfile . PHP_EOL_OUTPUT;

    // output memory usage details
    $usage = memory_get_peak_usage(true);
    logLineToAll($logfile_handle, MEM_PEAK_STR . ': ' . ($usage) . ' B');
    logLineToAll($logfile_handle, MEM_PEAK_STR . ': ' . ($usage / 1024) . ' KiB');
    logLineToAll($logfile_handle, MEM_PEAK_STR . ': ' . ($usage / 1024 / 1024) . ' MiB');
    if (
        $archive_files &&
        $archive_created
    ) {
        logLineToAll($logfile_handle, 'zip creation: ' . ($zip_end - $zip_start) . ' seconds');
    }
    logLineToAll($logfile_handle, 'Completed in: ' . (microtime(true) - $start) . ' seconds');

    // close the logfile handle
    if ($logfile_handle) {
        fclose($logfile_handle);
    }

    // delete extracted rules file if it exists
    if (
        $rules_file_zip_cleanup &&
        file_exists($rules_file)
    ) {
        unlink($rules_file);
    }

    // output end element in browser to prevent invalid html which might cause display issues
    if (defined('END')) {
        echo END;
    }
};

$sig_handler = function() use(
    &$logfile_handle,
    &$start)
{
    logLineToAll($logfile_handle, '');
    logLineToAll($logfile_handle, 'The scanner was killed after ' . (microtime(true) - $start) . ' seconds.');
};

// register shutdown handler
register_shutdown_function($shutdown);

// catch SIGTERM
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
}

// register handler for SIGTERM which calls exit() and therefore calls $shutdown
if (function_exists('pcntl_signal')) {
    pcntl_signal(SIGTERM, $sig_handler);
}

// generate file list and exclude files with specific extensions
if ($create_files_list || $use_existing_files_list) {
    // change the command for the file list
    $scan_command = $yara_binary . ' -' . $scan_options . ' ' . $rules_file . ' --scan-list ' . $files_list . ' 2>&1';

    if (!$use_existing_files_list) {
        // create file for the list
        $files_list_handle = fopen($files_list, 'w');

        // get all files
        $files = findFilesWithoutExcludedExtensions(
            $scan_path,
            $files_list_excluded_extensions,
            $logfile_inode,
            $scanner_inode
        );

        // write each file path to the list
        if (isset($files)) {
            foreach ($files as $file) {
                fwrite($files_list_handle, $file . PHP_EOL);
                fflush($files_list_handle);
            }
        }

        // close the file
        fclose($files_list_handle);
    }
}

// add logfile creation details
fwrite($logfile_handle, 'Logfile created with ' . $product . ' v' . $version . ' by ' . $author . PHP_EOL . PHP_EOL);
fflush($logfile_handle);

// add scan start details
logLineToAll($logfile_handle, 'Scan started at ' . $start);

// try to get the libzip version
$libzip_version = 'not defined';
if (defined('ZipArchive::LIBZIP_VERSION')) {
    $libzip_version = ZipArchive::LIBZIP_VERSION;
}

// write details about commands, rules, system and openssl to logfile
fwrite($logfile_handle, CMD_STR . ': ' . $scan_command . PHP_EOL);
fwrite($logfile_handle, RULES_FILE_STR . ' (original): ' . $rules_file_original . PHP_EOL);
fwrite($logfile_handle, RULES_FILE_STR . ' (used): ' . $rules_file . PHP_EOL);
fwrite($logfile_handle, RULES_FILE_STR . ' hash: ' . $rules_file_hash . PHP_EOL);
fwrite($logfile_handle, 'System: ' . php_uname() . PHP_EOL);
fwrite($logfile_handle, 'OpenSSL: ' . OPENSSL_VERSION_TEXT . PHP_EOL);
fwrite($logfile_handle, 'PHP version: ' . phpversion() . PHP_EOL);
fwrite($logfile_handle, 'zip extension version: ' . phpversion('zip') . PHP_EOL);
fwrite($logfile_handle, 'libzip version: ' . $libzip_version . PHP_EOL);
fflush($logfile_handle);

// reset the exit code
$exit_code = null;

// initialize archive variable
$archive_created = null;

// initialize archive variable
$archive_zip = null;

// get first line from version output
$yara_version_lines = runCommand($version_command, $exit_code);
$yara_version = $yara_version_lines->current();

// check if it is a version string and write it to the logfile
if (version_compare($yara_version, '0.0.1', '>=')) {
    fwrite($logfile_handle, 'yara version: ' . $yara_version . PHP_EOL);
    fflush($logfile_handle);
}

fwrite($logfile_handle, PHP_EOL);
fflush($logfile_handle);

// reset the exit code
$exit_code = null;

// run the scan command
$scan_lines = runCommand($scan_command, $exit_code);

// try to create archive file
if ($archive_files) {
    try {
        $archive_zip = new ZipArchive;

        // try to create the zip file
        $archive_created = $archive_zip->open($archivefile, ZipArchive::CREATE);
    } catch (Exception $exception) {
        // output exceptions for debugging, optionally write to log?
        echo EXCEPTION_STR . ': ' . $exception->getMessage() . PHP_EOL_OUTPUT;
    }

    // disable encryption if the encryption method is not available
    if (
        $archive_created &&
        $archive_encrypt &&
        !$encryption_method
        //!version_compare(ZipArchive::LIBZIP_VERSION, '1.2.0', '>=')
    ) {
        $archive_encrypt = false;
    }
}

$files_array = [];

// stream output to logfile
foreach ($scan_lines as $scan_line) {
    // show some progress
    echo PROGRESS_CHAR_STR . ' ';

    // archive single files matched by rules
    if (strpos($scan_line, $split_lines_by)) {
        $scan_line_parts = explode($split_lines_by, $scan_line);
        $scan_line_parts = array_slice($scan_line_parts, 1);
        $scan_line_filepath = implode($split_lines_by, $scan_line_parts);

        if (
            isset($scan_line_filepath) &&
            file_exists($scan_line_filepath) &&
            !is_dir($scan_line_filepath) &&
            is_readable($scan_line_filepath)
            // is_file(...)
        ) {
            // prevent that the logfile and the scanner are added?
            $scan_line_filepath_stat = stat($scan_line_filepath);
            $scan_line_filepath_inode = $scan_line_filepath_stat['ino'];
            $scan_line_filepath_stat_ctime = $scan_line_filepath_stat['ctime'];
            $scan_line_filepath_stat_mtime = $scan_line_filepath_stat['mtime'];

            if (
                $scan_line_filepath_inode !== $logfile_inode &&
                $scan_line_filepath_inode !== $scanner_inode
            ) {
                // extra check to prevent that the PHP engine has to check for collisions
                if (!isset($files_array[$scan_line_filepath_inode])) {
                //if (!array_key_exists($scan_line_filepath_inode, $files_array)) {
                    // path to file with filename, filename
                    $files_array[$scan_line_filepath_inode] = $scan_line_filepath;
                }

                if (
                    $matched_earliest_ctime === 0 ||
                    $scan_line_filepath_stat_ctime < $matched_earliest_ctime
                ) {
                    $matched_earliest_ctime = $scan_line_filepath_stat_ctime;
                }

                if (
                    $matched_earliest_mtime === 0 ||
                    $scan_line_filepath_stat_mtime < $matched_earliest_mtime
                ) {
                    $matched_earliest_mtime = $scan_line_filepath_stat_mtime;
                }
            }
            // optionally output the file
            // echo $scan_line_filepath . PHP_EOL_OUTPUT;
        }
    }

    // write output to logfile
    fwrite($logfile_handle, $scan_line . PHP_EOL);
    fflush($logfile_handle);
}

if (
    $archive_files &&
    $archive_created &&
    count($files_array) > 0
) {
    foreach ($files_array as $key => $files_array_current_path) {
        $archive_zip->addFile($files_array_current_path);
        // CM_DEFAULT, CM_STORE, CM_SHRINK, CM_SHRINK_1 - CM_SHRINK_4, CM_IMPLODE, CM_DEFLATE, CM_DEFLATE64, CM_PKWARE_IMPLODE, CM_BZIP2, CM_LZMA, CM_LZMA2, CM_ZSTD, CM_XZ
        // $archive_zip->setCompressionName($scan_line_filepath, ZipArchive::CM_DEFLATE);
        if ($archive_encrypt) {
            // EM_TRAD_PKWARE, EM_AES_128, EM_AES_192, EM_AES_256
            $archive_zip->setEncryptionName(
                $files_array_current_path,
                $encryption_method,
                $zip_password
            );
        }
    }
} 

$end = microtime(true);
