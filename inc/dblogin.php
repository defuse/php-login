<?php
/*
 * This code is hereby placed into the public domain by its author Taylor 
 * Hornby. It may be freely used for any purpose whatsoever.
 *
 * Developer's Contact Information:
 * WWW:     https://defuse.ca/
 * EMAIL:   <fillmein>
 * 
 * ***DISCLAIMER***
 *
 * ALL PUBLIC DOMAIN MATERIAL IS OFFERED AS-IS. NO REPRESENTATIONS OR
 * WARRANTIES OF ANY KIND ARE MADE CONCERNING THE MATERIALS, EXPRESS,
 * IMPLIED, STATUTORY OR OTHERWISE, INCLUDING, WITHOUT LIMITATION,
 * WARRANTIES OF TITLE, MERCHANTIBILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * NONINFRINGEMENT, OR THE ABSENCE OF LATENT OR OTHER DEFECTS, ACCURACY, OR
 * THE PRESENCE OF ABSENCE OF ERRORS, WHETHER OR NOT DISCOVERABLE.
 * 
 * Limitation on Liability.
 * 
 * IN NO EVENT WILL THE AUTHOR(S), PUBLISHER(S), OR PRESENTER(S) OF ANY
 * PUBLIC DOMAIN MATERIAL BE LIABLE TO YOU ON ANY LEGAL THEORY FOR ANY
 * SPECIAL, INCIDENTAL, CONSEQUENTIAL, PUNITIVE OR EXEMPLARY DAMAGES
 * ARISING OUT OF THIS LICENSE OR THE USE OF THE WORK, EVEN IF THE
 * AUTHOR(S), PUBLISHER(S), OR PRESENTER(S) HAVE BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
*/
    // Don't make the password a global variable
    function loginToUserSystemDatabase()
    {
        $username = "root";
        $password = "newpassword";
       
        $result = FALSE;
        try
        {
            $result = new PDO('mysql:host=localhost;dbname=securelogin', 
                                $username, 
                                $password, 
                                array(PDO::ATTR_PERSISTENT => true)
                                );
        }
        catch(Exception $e)
        {
            $result = FALSE;
        }

        // Unset secret data explitly in case this code is ever moved
        unset($username);
        unset($password);
        return $result;
    }

    $USERDB = loginToUserSystemDatabase();
    if($USERDB == FALSE)
    {
        syslog(LOG_EMERG, "Cannot connect to user account database.");
        die(); //TODO: Nicer error page
    }

    $SESSDB = $USERDB; // To make it easy to separate session from the rest.
?>
