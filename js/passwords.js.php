<?php
    require_once('../inc/security.conf.php');

    header('content-type: application/javascript');
?>
function computeHash(username, password)
{
    var siteSpecificSalt = "<?php echo addslashes(SITE_SPECIFIC_IV); ?>";
    var iterations = <?php echo CLIENTSIDE_HASH_ITERATIONS; ?>;
    var hashOctets = <?php echo CLIENTSIDE_HASH_OCTETS; ?>;
    var hashAlgorithm = "<?php echo CLIENTSIDE_HASH_ALGORITHM; ?>";

    var prf = null;

    switch(hashAlgorithm)
    {
        case "sha256":
            prf = sjcl.misc.hmac;
        break;
        default:
            alert('CONFIGURATION ERROR: Unsupported client-side hash algorithm.');
            return;
    }
    var passwordBits = sjcl.codec.utf8String.toBits(password);
    var salt = sjcl.codec.utf8String.toBits(username.toLowerCase() + siteSpecificSalt);
    var hash = sjcl.misc.pbkdf2(passwordBits, salt, iterations, hashOctets * 8, prf);
    hash = sjcl.codec.hex.fromBits(hash);
    return hash;
}

function conformsToPolicy(password)
{
    var minLength = <?php echo PASSWORDPOLICY_MINLENGTH; ?>;
    var maxLength = <?php echo PASSWORDPOLICY_MAXLENGTH; ?>;
    var requireDigit = <?php echo (PASSWORDPOLICY_REQUIRE_DIGIT) ? "true" : "false"; ?>;
    var requireSymbol = <?php echo (PASSWORDPOLICY_REQUIRE_SYMBOL) ? "true" : "false"; ?>;
    var requireUpperAlpha = <?php echo (PASSWORDPOLICY_REQUIRE_UPPERALPHA) ? "true" : "false"; ?>;
    var requireLowerAlpha = <?php echo (PASSWORDPOLICY_REQUIRE_LOWERALPHA) ? "true" : "false"; ?>;

    if(password.length > maxLength || password.length < minLength)
        return false;

    if(requireDigit && !containsAny(password, "0123456789"))
        return false;
    if(requireSymbol && !containsAny(password, "~`!@#$%^&*()_+-={[}]|\\:;\"'<,>.?/"))
        return false;
    if(requireUpperAlpha && !containsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        return false;
    if(requireLowerAlpha && !containsAny(password, "abcdefghijklmnopqrstuvwxyz"))
        return false;

    return true;
}

function containsAny(password, symbols)
{
    var found = false;
    for(var i = 0; i < symbols.length; i++)
    {
        if(password.indexOf(symbols.substring(i, i+1)) > -1)
            found = true;
    }
    return found;
}
