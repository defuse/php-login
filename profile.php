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

include('inc/require_login.php');
include('ui/page_top.php');
include('security/Escape.php');

$saved = false;
if(isset($_POST['save']))
{
    $new = $_POST['notepad'];
    $USER->setAttribute('notepad', $new);
    $saved = true;
}

?>
<?php 
    echo "<h1>Hello, " . Escape::html($USER->propername()) . "</h1>";
?>
<h2>Secure Notepad</h2>
<?php
    if($saved)
    {
    ?>
        <div style="margin-top: 10px; margin-bottom: 10px; padding: 5px; background-color: #00FFFF; border: solid black 1px; width: 300px;">
        Notepad saved.
        </div>
    <?
    }
?>
<form action="profile.php" method="post">
<textarea name="notepad" rows="30" cols="80" ><?php
    $notepad = $USER->getAttribute('notepad');
    if($notepad !== FALSE)
    {
        echo Escape::html($notepad);
    }
?></textarea><br />
<input type="submit" name="save" value="Save Notepad" />
</form>

<?php
    include('ui/page_end.php');
?>
