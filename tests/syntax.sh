find -type f -iname "*.php" -exec php -l {} \;
find -type f -iname "*.php" -exec tclsh ./tests/phplint/phplint.tcl {} \;
