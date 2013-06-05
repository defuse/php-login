<?php

//TODO: debug mode to write emails to a file instead
require_once('inc/security.conf.php');

// MUST end in a forward slash.
define("EMAIL_TEMPLATE_ROOT", "email_templates/");

define("EMAIL_DEBUG_ENABLE", true);
define("EMAIL_DEBUG_FILE", "/home/firexware/email.txt");

//TODO: USE EMAIL_FROM_ADDR (not here)

//TODO: documetn
// This class will contain all email *message* related functions
// It should be as low level as possible, providing text formatting only
//Eventually it should read template files and do some simple macro substitution
class Email
{
    public static function SendMacroMail($src_addr, $dest_addr, $subject, $template_name, $macros)
    {
        $pt = file_get_contents(EMAIL_TEMPLATE_ROOT . "pt/$template_name.txt");
        $html = file_get_contents(EMAIL_TEMPLATE_ROOT . "html/$template_name.htm");

        if($pt === FALSE || $html === FALSE)
            return FALSE;

        foreach($macros as $search => $replace)
        {
            $pt = str_replace($search, $replace, $pt);
            $html = str_replace($search, $replace, $html);
        }
        
        return self::SendMail($src_addr, $dest_addr, $subject, $pt, $html);
    }

    /*
     * Sends an email.
     * $src_addr - The email address that will show up as the sender.
     * $dest_addr - The destination email address.
     * $subject - The subject of the email.
     * $plainbody - What the recipient will see if they have HTML email disabled.
     * $htmlbody - What the recipient will see if they have HTML email enabled.
     */ 
    public static function SendMail($src_addr, $dest_addr, $subject, $plainbody, $htmlbody)
    {
        //TODO: UTF-8 proper?
        //TODO: return-path header verify
        //TODO: Lines of characters in the body MUST be limited to 998 characters, and SHOULD
        // be limited to 78 characters excluding the CRLF
        //TODO: CR and LF must only occur togeather as CRLF; they must not appear independantly in the body
        //TODO: http://www.faqs.org/rfcs/rfc2822.html (lots of subtleties that need to be dealt with)
        //TODO: Readme.txt in pt and HTML folder explaining any non-enforced formatting rules

        // To include both plain text and HTML body, we use the multipart/alternative format.
        // Reference: http://www.w3.org/Protocols/rfc1341/7_2_Multipart.html

        // Boundary separates the plain text body and HTML body
        $boundary = bin2hex(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM));
        $headers = "From: $src_addr\r\n" .
                   "Reply-To: $src_addr\r\n" .
                   "Content-Type: multipart/alternative; boundary=$boundary\r\n";

        $content = "--$boundary\r\n" .
                    // Plain text section headers
                   "Content-Type: text/plain; charset=utf-8; format=flowed; delsp=yes\r\n" .
                   "\r\n" .
                   $plainbody . "\r\n" .
                   "--$boundary\r\n" .  
                   // HTML section headers
                   "Content-Type: text/html; charset=utf-8\r\n" .
                   "Content-Transfer-Encoding: quoted-printable\r\n" .
                   "\r\n" .
                   $htmlbody . "\r\n" .
                   "--$boundary\r\n";

        if(EMAIL_DEBUG_ENABLE)
        {
            $mail = "---BEGIN MAIL ----\n" . $headers . "\n\n" . $content;
            file_put_contents(EMAIL_DEBUG_FILE, $mail, FILE_APPEND);
        }
        else
        {
            return mail($dest_addr, $subject, $content, $headers);
        }
    }
}

?>
