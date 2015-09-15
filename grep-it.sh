#!/bin/bash
#
# A simple greper for code, loot, IT-tech-stuff-the-customer-throws-at-you.
# Tries to find IT security and privacy related stuff.
# For pentesters.
#
# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <floyd at floyd dot ch> wrote this file. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return
# floyd http://floyd.ch @floyd_ch <floyd at floyd dot ch>
# July 2013
# ----------------------------------------------------------------------------
#
# Requirements:
# - GNU grep. If you have OSX, install from ports or so. Reason: we need regex match -P
# - rm command. Reason: if grep doesn't match anything we remove the corresponding output file
# - mkdir command. Reason: we need to make the $TARGET directory
#
# Howto:
# - Customize the "OPTIONS" section below to your needs
# - Copy this file to the parent directory which you want to grep
# - run it like this: ./grep-it.sh ./directory-to-grep-through/
#
# Output:
# Default output is optimised to be viewed with "less -R ./grep-output/*" and then you can hop from one file to the next with :n
# and :p. The cat command works fine. If you want another editor you should probably remove --color=always and other grep arguments
# Output files have the following naming conventions (separated by underscore):
# - priority: 1-5, where 1 is more interesting (low false positive rate, certainty of "vulnerability") and 5 is only "you might want to have a look"
# - section: eg. java or php
# - name of what we looked for
#

###
#OPTIONS - please customize
###
GREP_COMMAND="/opt/local/bin/grep" #or just "grep"
RM_COMMAND="rm"
ADDITIONAL_GREP_ARGUMENTS="-n -A 1 -B 3"
#Open the colored outputs with "less -R" or cat, otherwise remove --color=always
COLOR_ARGUMENTS="--color=always"
#Output folder if not otherwise specified on the command line
TARGET="./grep-output"
#Write the comment to each file at the beginning
WRITE_COMMENT="true"
#Sometimes we look for composite words with wildcard, eg. root.{0,20}detection, this is the maximum
#of random characters that can be in between. The higher the value the more strings will potentially be flagged.
WILDCARD_SHORT=20
WILDCARD_LONG=200
WILDCARD_EXTRA_LONG=500
#Do all greps in background with &
#ATTENTION: THIS WOULD SPAWN A SHIT LOAD OF PROCESSES ON YOUR SYSTEM (LET'S SAY 500)
#           ADDITIONALLY WE ARE NOT ABLE TO CLEAN UP AFTER WE FINISH (REMOVE EMPTY FILES)
#           USE WITH CAUTION
BACKGROUND="false"

#In my opinion I would always leave all the options below here on true,
#because I did find strange android code in iphone apps and vice versa. I would only
#change it if grep needs very long, you are greping a couple of hundred apps
#or if you have any other performance issues with this script.
DO_JAVA="true"
DO_JSP="true"
DO_SPRING="true"
DO_STRUTS="true"

DO_DOTNET="true"

DO_PHP="true"

DO_HTML="true"
DO_JAVASCRIPT="true"
DO_MODSECURITY="true"

DO_MOBILE="true"
DO_ANDROID="true"
DO_IOS="true"

#C and derived languages
DO_C="true"

DO_MALWARE_DETECTION="true"

DO_CRYPTO_AND_CREDENTIALS="true"

DO_GENERAL="true"

###
#END OPTIONS
#Normally you don't have to change anything below here...
###

###
#CODE SECTION
#As a user of this script you shouldn't need to care about the stuff that is coming down here...
###

# Conventions if you add new regexes:
# - First think about which sections you want to put a new rule
# - Don't use * in regex but use {0,X} instead. See WILDCARD_ variables below for configurable values of X.
# - make sure functions calls with space before bracket will be found, e.g. "extract (bla)" is allowed in PHP
# - If in doubt, prefer to make two regex and output files rather then joining regexes with |. If one produces false positives it is really annoying to search for the true positives of the other regex.
# - Take care with single/double quoted strings. From the bash manual:
# 3.1.2.2 Single Quotes
# Enclosing characters in single quotes (‘'’) preserves the literal value of each character within the quotes. A single quote may not occur between single quotes, even when preceded by a backslash.
# 3.1.2.3 Double Quotes
# Enclosing characters in double quotes (‘"’) preserves the literal value of all characters within the quotes, with the exception of ‘$’, ‘`’, ‘\’, and, when history expansion is enabled, ‘!’. The characters ‘$’ and ‘`’ retain their special meaning within double quotes (see Shell Expansions). The backslash retains its special meaning only when followed by one of the following characters: ‘$’, ‘`’, ‘"’, ‘\’, or newline. Within double quotes, backslashes that are followed by one of these characters are removed. Backslashes preceding characters without a special meaning are left unmodified. A double quote may be quoted within double quotes by preceding it with a backslash. If enabled, history expansion will be performed unless an ‘!’ appearing in double quotes is escaped using a backslash. The backslash preceding the ‘!’ is not removed. The special parameters ‘*’ and ‘@’ have special meaning when in double quotes (see Shell Parameter Expansion).
#
# TODO: 
#
# TODO longterm (aka "probably never but I know I should")
# - Write a test that will check if the examples really match the regex
# - Add/improve comments everywhere
# - Add comments about case-sensitivity and whitespace behavior of languages and other syntax rules that might influence our regexes

if [ $# -lt 1 ]
then
  echo "Usage: `basename $0` directory-to-grep-through"
  exit 0
fi

if [ "$1" = "." ]
then
  echo "You are shooting yourself in the foot. Do not grep through . but rather cd into parent directory and mv `basename $0` there."
  echo "READ THE HOWTO (3 lines)"
  exit 0
fi

if [ $# -eq 2 ]
then
  #argument without last /
  TARGET=${2%/}
fi

GREP_ARGUMENTS="-rP"
STANDARD_GREP_ARGUMENTS="$ADDITIONAL_GREP_ARGUMENTS $GREP_ARGUMENTS $COLOR_ARGUMENTS"

#argument without last /
SEARCH_FOLDER=${1%/}

mkdir "$TARGET"

echo "Your standard grep arguments (customize in OPTIONS setting): $STANDARD_GREP_ARGUMENTS"
echo "Output will be put into this folder: $TARGET"
echo "You are currently greping through folder: $SEARCH_FOLDER"
sleep 2

function search()
{
    COMMENT="$1"
    EXAMPLE="$2"
    FALSE_POSITIVES_EXAMPLE="$3"
    SEARCH_REGEX="$4"
    OUTFILE="$5"
    ARGS_FOR_GREP="$6" #usually just -i for case insensitive or empty
    #echo "$COMMENT, $SEARCH_REGEX, $OUTFILE, $ARGS_FOR_GREP, $WRITE_COMMENT, $BACKGROUND, $GREP_COMMAND, $STANDARD_GREP_ARGUMENTS, $TARGET"
    echo "Searching (background:$BACKGROUND args for grep:$ARGS_FOR_GREP) for $SEARCH_REGEX --> writing to $OUTFILE"
    if [ "$WRITE_COMMENT" = "true" ]; then
        echo "# Info: $COMMENT" >> "$TARGET/$OUTFILE"
        echo "# Filename $OUTFILE" >> "$TARGET/$OUTFILE"
        echo "# Example: $EXAMPLE" >> "$TARGET/$OUTFILE"
        echo "# False positive example: $FALSE_POSITIVES_EXAMPLE" >> "$TARGET/$OUTFILE"
        echo "# Grep additional args: $ARGS_FOR_GREP" >> "$TARGET/$OUTFILE"
        echo "# Search regex: $SEARCH_REGEX" >> "$TARGET/$OUTFILE"
    fi
    if [ "$BACKGROUND" = "true" ]; then
        $GREP_COMMAND $ARGS_FOR_GREP $STANDARD_GREP_ARGUMENTS "$SEARCH_REGEX" "$SEARCH_FOLDER" >> "$TARGET/$OUTFILE" &
    else
        $GREP_COMMAND $ARGS_FOR_GREP $STANDARD_GREP_ARGUMENTS "$SEARCH_REGEX" "$SEARCH_FOLDER" >> "$TARGET/$OUTFILE"
        if [ $? -ne 0 ]; then
           #echo "Last grep didn't have a result, removing $OUTFILE"
           $RM_COMMAND "$TARGET/$OUTFILE"
        fi
    fi
}

function true_and_false_positive_checker()
{
    COMMENT="$1"
    EXAMPLE="$2"
    FALSE_POSITIVES_EXAMPLE="$3"
    SEARCH_REGEX="$4"
    OUTFILE="$5"
    ARGS_FOR_GREP="$6"
    #echo "$COMMENT, $SEARCH_REGEX, $OUTFILE, $ARGS_FOR_GREP, $WRITE_COMMENT, $BACKGROUND, $GREP_COMMAND, $STANDARD_GREP_ARGUMENTS, $TARGET"
    #TODO:
    echo "$FALSE_POSITIVES_EXAMPLE" >> "tests/false_positives.txt"
    $GREP_COMMAND $ARGS_FOR_GREP $STANDARD_GREP_ARGUMENTS "$SEARCH_REGEX" "$SEARCH_FOLDER" >> "$TARGET/$OUTFILE"
    
}


#The Java stuff
if [ "$DO_JAVA" = "true" ]; then
    
    echo "#Doing Java"
    
    search "All Strings between double quotes. Like the command line tool 'strings' for Java code." \
    'String bla = "This is a Java String";' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '"[^"]{4,500}"' \
    "3_java_strings.txt" \
    "-o" #Special case, we only want to show the strings themselves, therefore -o to output the match only
    
    search "All javax.crypto usage" \
    'import javax.crypto.bla;' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'javax.crypto' \
    "3_java_crypto_javax-crypto.txt"
    
    search "Bouncycastle is a common Java crypto provider" \
    'import org.bouncycastle.bla;' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "bouncy.{0,$WILDCARD_SHORT}castle" \
    "3_java_crypto_bouncycastle.txt" \
    "-i"
    
    search "SecretKeySpec is used to initialize a new encryption key: instance of SecretKey, often passed in the first argument as a byte[], which is the actual key" \
    'new SecretKeySpec(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'new\sSecretKeySpec\(' \
    "1_java_crypto_new-SecretKeySpec.txt" \
    "-i"
    
    search "PBEKeySpec( is used to initialize a new encryption key: instance of PBEKeySpec, often passed in the first argument as a byte[], which is the actual key" \
    'new PBEKeySpec(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'new\sPBEKeySpec\(' \
    "1_java_crypto_new-PBEKeySpec(.txt" \
    "-i"
    
    search "GenerateKey is another form of making a new instance of SecretKey, depending on the use case randomly generates one on the fly. It's interesting to see where the key goes next, where it's stored or accidentially written to a log file." \
    '.generateKey()' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.generateKey\(' \
    "2_java_crypto_generateKey.txt" \
    "-i"
    
    search "Occurences of KeyGenerator.getInstance(ALGORITHM) it's interesting to see where the key goes next, where it's stored or accidentially written to a log file." \
    'KeyGenerator.getInstance(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'KeyGenerator\.getInstance\(' \
    "2_java_crypto_keygenerator-getinstance.txt" \
    "-i"
    
    search "The Random class shouldn't be used for crypthography in Java, the SecureRandom should be used instead." \
    'Random random = new Random();' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'new Random\(' \
    "2_java_crypto_random.txt" \
    
    search "Message digest is used to generate hashes" \
    'messagedigest' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'messagedigest' \
    "2_java_crypto_messagedigest.txt" \
    "-i"
    
    search "KeyPairGenerator, well, to generate key pairs, see http://docs.oracle.com/javase/7/docs/api/java/security/KeyPairGenerator.html . It's interesting to see where the key goes next, where it's stored or accidentially written to a log file." \
    'KeyPairGenerator(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'KeyPairGenerator\(' \
    "1_java_crypto_keypairgenerator.txt"
    
    search "String comparisons have to be done with .equals() in Java, not with == (won't work). Attention: False positives often occur if you used a decompiler to get the Java code, additionally it's allowed in JavaScript." \
    '    toString(  )    ==' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "toString\(\s{0,$WILDCARD_SHORT}\)\s{0,$WILDCARD_SHORT}==" \
    "4_java_string_comparison1.txt"
    
    search "String comparisons have to be done with .equals() in Java, not with == (won't work). Attention: False positives often occur if you used a decompiler to get the Java code, additionally it's allowed in JavaScript." \
    ' ==     toString() ' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "==\s{0,$WILDCARD_SHORT}toString\(\s{0,$WILDCARD_SHORT}\)" \
    "4_java_string_comparison2.txt"
    
    search "String comparisons have to be done with .equals() in Java, not with == (won't work). Attention: False positives often occur if you used a decompiler to get the Java code, additionally it's allowed in JavaScript." \
    ' ==     "' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "==\s{0,$WILDCARD_SHORT}\"" \
    "4_java_string_comparison3.txt"
    
    search "String comparisons: Filters and conditional decisions on user input should better be done with .equalsIgnoreCase() in Java in most cases, so that the clause doesn't miss something (e.g. think about string comparison in filters) or long switch case. Another problem with equals and equalsIgnoreCase for checking user supplied passwords or Hashes or HMACs or XYZ is that it is not a time-consistent method, therefore allowing timing attacks." \
    '.equals(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'equals\(' \
    "2_java_string_comparison_equals.txt"
    
    search "String comparisons: Filters and conditional decisions on user input should better be done with .equalsIgnoreCase() in Java in most cases, so that the clause doesn't miss something (e.g. think about string comparison in filters) or long switch case. Another problem with equals and equalsIgnoreCase for checking user supplied passwords or Hashes or HMACs or XYZ is that it is not a time-consistent method, therefore allowing timing attacks." \
    '.equalsIgnoreCase(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'equalsIgnoreCase\(' \
    "2_java_string_comparison_equalsIgnoreCase.txt"
    
    search "The syntax for SQL executions start with execute." \
    'executeBlaBla(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "execute.{0,$WILDCARD_SHORT}\(" \
    "2_java_sql_execute.txt"
    
    search "SQL syntax" \
    'addBatch(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "addBatch\(" \
    "3_java_sql_addBatch.txt"
    
    search "SQL prepared statements, can go wrong if you prepare after you use user supplied input in the query syntax..." \
    'prepareStatement(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "prepareStatement\(" \
    "2_java_sql_prepareStatement.txt"
    
    search "Method to set HTTP headers in Java" \
    '.setHeader(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.setHeader\(" \
    "3_java_http_setHeader.txt"
    
    search "Method to set HTTP headers in Java" \
    '.addCookie(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.addCookie\(" \
    "3_java_http_addCookie.txt"
        
    search "Method to send HTTP redirect in Java" \
    '.sendRedirect(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.sendRedirect\(" \
    "3_java_http_sendRedirect.txt"
    
    search "Java add HTTP header" \
    '.addHeader(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.addHeader\(" \
    "3_java_http_addHeader.txt"
    
    search "Java get HTTP header" \
    '.getHeaders(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.getHeaders\(" \
    "3_java_http_getHeaders.txt"
    
    search "Java get HTTP cookies" \
    '.getCookies(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.getCookies\(" \
    "3_java_http_getCookies.txt"
    
    search "Java get remote host" \
    '.getRemoteHost(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.getRemoteHost\(" \
    "3_java_http_getRemoteHost.txt"
    
    search "Java get content type" \
    '.getContentType(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.getContentType\(" \
    "3_java_http_getContentType.txt"
    
    search "Java HTTP or XML local name" \
    '.getLocalName(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.getLocalName\(" \
    "3_java_http_getLocalName.txt"
    
    search "Java generic parameter fetching" \
    '.getParameterBlabla(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.getParameter.{0,$WILDCARD_SHORT}\(" \
    "3_java_http_getParameter.txt"
    
    search "Potential tainted input in string format." \
    'String.format(\"bla-%s\"+taintedInput, variable);' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "String\.format\(\s{0,$WILDCARD_SHORT}\"[^\"]{1,$WILDCARD_LONG}\"\s{0,$WILDCARD_SHORT}\+" \
    "3_java_format_string1.txt"
    
    search "Potential tainted input in string format." \
    'String.format(variable)' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "String\.format\(\s{0,$WILDCARD_SHORT}[^\"]" \
    "3_java_format_string2.txt"
    
    search "Java ProcessBuilder" \
    'ProcessBuilder' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'ProcessBuilder' \
    "2_java_ProcessBuilder.txt" \
    "-i"
    
    search "HTTP session timeout" \
    'setMaxInactiveInterval()' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'setMaxInactiveInterval\(' \
    "3_java_servlet_setMaxInactiveInterval.txt"
    
    #Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
    search "Find out which Java Beans get persisted with javax.persistence" \
    '@Entity' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '@Entity|@ManyToOne|@OneToMany|@OneToOne|@Table|@Column' \
    "3_java_persistent_beans.txt" \
    "-l" #Special case, we only want to know matching files to know which beans get persisted, therefore -l to output matching files
    
    #Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
    search "The source code shows the database table/column names... e.g. if you find a sql injection later on, this will help for the exploitation" \
    '@Column' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '@Column\(' \
    "3_java_persistent_columns_in_database.txt"
    
    #Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
    search "The source code shows the database table/column names... e.g. if you find a sql injection later on, this will help for the exploitation" \
    '@Table' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '@Table\(' \
    "3_java_persistent_tables_in_database.txt"
    
    search "Find out which Java classes do any kind of io" \
    'java.net.' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'java\.net\.' \
    "4_java_io_java_net.txt" \
    "-l" #Special case, we only want to know matching files to know which beans get persisted, therefore -l to output matching files
    
    search "Find out which Java classes do any kind of io" \
    'java.io.' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'java\.io\.' \
    "4_java_io_java_io.txt" \
    "-l" #Special case, we only want to know matching files to know which beans get persisted, therefore -l to output matching files
    
    search "Find out which Java classes do any kind of io" \
    'javax.servlet' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'javax\.servlet' \
    "4_java_io_javax_servlet.txt" \
    "-l" #Special case, we only want to know matching files to know which beans get persisted, therefore -l to output matching files
    
    search "Find out which Java classes do any kind of io" \
    'org.apache.http' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'org\.apache\.http' \
    "4_java_io_apache_http.txt" \
    "-l" #Special case, we only want to know matching files to know which beans get persisted, therefore -l to output matching files
    
    search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
    'String password' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "string .{0,$WILDCARD_SHORT}password" \
    "4_java_confidential_data_in_strings_password.txt" \
    "-i"
    
    search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
    'String secret' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "string .{0,$WILDCARD_SHORT}secret" \
    "4_java_confidential_data_in_strings_secret.txt" \
    "-i"
    
    search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
    'String key' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "string .{0,$WILDCARD_SHORT}key" \
    "4_java_confidential_data_in_strings_key.txt" \
    "-i"
    
    search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
    'String cvv' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "string .{0,$WILDCARD_SHORT}cvv" \
    "4_java_confidential_data_in_strings_cvv.txt" \
    "-i"
    
    search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
    'String user' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "string .{0,$WILDCARD_SHORT}user" \
    "4_java_confidential_data_in_strings_user.txt" \
    "-i"
    
    search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
    'String passcode' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "string .{0,$WILDCARD_SHORT}passcode" \
    "4_java_confidential_data_in_strings_passcode.txt" \
    "-i"
    
    search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
    'String passphrase' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "string .{0,$WILDCARD_SHORT}passphrase" \
    "4_java_confidential_data_in_strings_passphrase.txt" \
    "-i"
    
    search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
    'String pin' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "string .{0,$WILDCARD_SHORT}pin" \
    "4_java_confidential_data_in_strings_pin.txt" \
    "-i"
    
    search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
    'String creditcard_number' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "string .{0,$WILDCARD_SHORT}credit" \
    "4_java_confidential_data_in_strings_credit.txt" \
    "-i"
    
    search "Attention: SSLSocketFactory means in general you will skip SSL hostname verification because the SSLSocketFactory can't know which protocol (HTTP/LDAP/etc.) and therefore can't lookup the hostname. Even Apache's HttpClient version 3 for Java is broken: see https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html" \
    'SSLSocketFactory' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'SSLSocketFactory' \
    "3_java_SSLSocketFactory.txt"
    
    search "It's very easy to construct a backdoor in Java with Unicode \u characters, even within multi line comments, see http://pastebin.com/iGQhuUGd and https://plus.google.com/111673599544007386234/posts/ZeXvRCRZ3LF ." \
    '\u0041\u0042' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\u00..\u00..' \
    "3_java_backdoor_as_unicode.txt" \
    "-i"
    
    search "CheckValidity method of X509Certificate in Java is a very confusing naming for developers new to SSL/TLS and has been used as the *only* check to see if a certificate is valid or not in the past. This method *only* checks the date-validity, see http://docs.oracle.com/javase/7/docs/api/java/security/cert/X509Certificate.html#checkValidity%28%29 : 'Checks that the certificate is currently valid. It is if the current date and time are within the validity period given in the certificate.'" \
    'paramArrayOfX509Certificate[0].checkValidity(); return;' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.checkValidity\(" \
    "2_java_ssl_checkValidity.txt"
    
    search "A simple search for getRuntime().exec()" \
    'getRuntime().exec()' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'getRuntime\(\)\.exec\(' \
    "2_java_runtime_exec_1.txt"
    
    search "A search for Process p = r.exec()" \
    'Process p = r.exec(args1);' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "Process.{0,$WILDCARD_SHORT}\.exec\(" \
    "2_java_runtime_exec_2.txt"
    
    search "Validation in Java can be done via javax.validation. " \
    'import javax.validation.bla;' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "javax.validation" \
    "2_java_javax-validation.txt"
    
    #Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
    search 'Validation in Java can be done via certain @constraint' \
    '@constraint' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '@constraint' \
    "2_java_constraint_annotation.txt"
    
    #Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
    search 'Lint will sometimes complain about security related stuff, this annotation deactivates the warning' \
    '@SuppressLint' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '@SuppressLint' \
    "2_java_suppresslint.txt"
    
fi


#The JSP specific stuff
if [ "$DO_JSP" = "true" ]; then
    
    echo "#Doing JSP"
    
    search "JSP redirect" \
    '.sendRedirect(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.sendRedirect\(' \
    "2_java_jsp_redirect.txt"
    
    search "JSP redirect" \
    '.forward(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.forward\(' \
    "2_java_jsp_forward_1.txt"
    
    search "JSP redirect" \
    ':forward' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    ':forward' \
    "2_java_jsp_forward_2.txt"
    
    search "Can introduce XSS" \
    'escape=false' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "escape\s{0,$WILDCARD_SHORT}=\s{0,$WILDCARD_SHORT}'?\"?\s{0,$WILDCARD_SHORT}false" \
    "1_java_jsp_xss_escape.txt" \
    "-i"
    
    search "Can introduce XSS" \
    'escapeXml=false' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "escapeXml\s{0,$WILDCARD_SHORT}=\s{0,$WILDCARD_SHORT}'?\"?\s{0,$WILDCARD_SHORT}false" \
    "1_java_jsp_xss_escapexml.txt" \
    "-i"
    
    search "Can introduce XSS when simply writing a bean property to HTML without escaping. Attention: there are now client-side JavaScript libraries using the same tags for templates!" \
    '<%=bean.getName()%>' \
    'Attention: there are now client-side JavaScript libraries using the same tags for templates!' \
    "<%=\s{1,$WILDCARD_SHORT}[A-Za-z0-9_]{1,$WILDCARD_LONG}.get[A-Za-z0-9_]{1,$WILDCARD_LONG}\(.{1,$WILDCARD_LONG}%>" \
    "1_java_jsp_property_to_html_xss.txt" \
    "-i"
    
    search "Java generic JSP parameter get" \
    '.getParameter(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.getParameter\(" \
    "3_java_jsp_property_to_html_xss.txt" \
    "-i"
    
    search "Can introduce XSS when simply writing a bean property to HTML without escaping." \
    'out.print(bean.getName());' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "out.printl?n?\(\"<[^\"]{1,$WILDCARD_LONG}='\"\);" \
    "1_java_jsp_out_print_to_html_xss.txt" \
    "-i"
    
    search "Can introduce XSS when simply writing a bean property to HTML without escaping." \
    'out.print("<option "+bean.getName()+"=jjjj");' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "out.printl?n?\(\"<.{1,$WILDCARD_LONG}\+.{1,$WILDCARD_LONG}\);" \
    "1_java_jsp_out_print_to_html_xss2.txt" \
    "-i"
    
    search "JSP file upload" \
    '<s:file test' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "<s:file\s" \
    "1_java_jsp_file_upload.txt" \
    "-i"
fi


#The Java Spring specific stuff
if [ "$DO_SPRING" = "true" ]; then
    
    echo "#Doing Java Spring"
    
    search "DataBinder.setAllowedFields. See e.g. http://blog.fortify.com/blog/2012/03/23/Mass-Assignment-Its-Not-Just-For-Rails-Anymore ." \
    'DataBinder.setAllowedFields' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'DataBinder\.setAllowedFields' \
    "2_java_spring_mass_assignment.txt" \
    "-i"
    
    search "stripUnsafeHTML, method of the Spring Surf Framework can introduce thinks like XSS, because it is not really protecting." \
    'stripUnsafeHTML' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'stripUnsafeHTML' \
    "2_java_spring_stripUnsafeHTML.txt" \
    "-i"
    
    search "stripEncodeUnsafeHTML, method of the Spring Surf Framework can introduce thinks like XSS, because it is not really protecting." \
    'stripEncodeUnsafeHTML' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'stripEncodeUnsafeHTML' \
    "2_java_spring_stripEncodeUnsafeHTML.txt" \
    "-i"
    
    search "RequestMapping method of the Spring Surf Framework to see how request URLs are mapped to classes." \
    '@RequestMapping(method=RequestMethod.GET, value={"/user","/user/{id}"})' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\@RequestMapping\(' \
    "3_java_spring_requestMapping.txt"
    
    search "ServletMapping XML of the Spring Surf Framework to see how request URLs are mapped to classes." \
    '<servlet-mapping><servlet-name>spring</servlet-name><url-pattern>*.html</url-pattern><url-pattern>/gallery/*</url-pattern><url-pattern>/galleryupload/*</url-pattern>' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '<servlet-mapping>' \
    "3_java_spring_servletMapping.txt"
    
    
fi

#The Java Struts specific stuff
if [ "$DO_SPRING" = "true" ]; then
    
    echo "#Doing Java Struts"
    
    search "Action mappings for struts where the validation is disabled" \
    'validate  =  "false' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "validate\s{0,$WILDCARD_SHORT}=\s{0,$WILDCARD_SHORT}'?\"?false" \
    "1_java_struts_deactivated_validation.txt" \
    "-i"
    
    search "see e.g. http://erpscan.com/press-center/struts2-devmode-rce-with-metasploit-module/" \
    'struts.devMode' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "struts\.devMode" \
    "1_java_struts_devMode.txt" \
    "-i"
fi


#The .NET specific stuff
if [ "$DO_DOTNET" = "true" ]; then
    
    echo "#Doing .NET"
    
    search ".NET View state enable" \
    'EnableViewStateMac' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "EnableViewStateMac" \
    "3_dotnet_viewState.txt"
    
    search "Potentially dangerous request filter message is not poping up when disabled, which means XSS in a lot of cases." \
    'ValidateRequest' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "ValidateRequest" \
    "2_dotnet_validate_request.txt"
    
    search "If you declare a variable 'unsafe' in .NET you can do pointer arythmetic and therefore introduce buffer overflows etc. again" \
    'int unsafe bla' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\sunsafe\s" \
    "2_dotnet_unsafe_declaration.txt"
    
    search "If you use Marshal in .NET you use an unsafe API and therefore you could introduce buffer overflows etc. again." \
    'Marshal' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "Marshal" \
    "2_dotnet_marshal.txt"
    
fi

#The PHP stuff
# - php functions are case insensitive: ImAgEcReAtEfRoMpNg()
# - whitespaces can occur everywhere, eg. 5.5 (-> 5.5) is different from 5 . 5 (-> "55"), see http://stackoverflow.com/questions/4884987/php-whitespaces-that-do-matter
if [ "$DO_PHP" = "true" ]; then
    
    echo "#Doing PHP"
    
    search "Tainted input, GET URL parameter" \
    '$_GET' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '$_GET' \
    "3_php_get.txt"
    
    search "Tainted input, POST parameter" \
    '$_POST' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '$_POST' \
    "3_php_post.txt"
    
    search "Tainted input, cookie parameter" \
    '$_COOKIE' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '$_COOKIE' \
    "3_php_cookie.txt"
    
    search "Tainted input. Using \$_REQUEST is a bad idea in general, as that means GET/POST exchangeable and transporting sensitive information in the URL is a bad idea (see HTTP RFC -> ends up in logs, browser history, etc.)." \
    '$_REQUEST' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '$_REQUEST' \
    "3_php_request.txt"
    
    search "Dangerous PHP function: popen" \
    'popen(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "popen\s{0,$WILDCARD_SHORT}\(" \
    "2_php_popen.txt" \
    "-i"
    
    search "Dangerous PHP function: proc_" \
    'proc_' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'proc_' \
    "2_php_proc.txt" \
    "-i"
    
    search "Dangerous PHP function: passthru" \
    'passthru(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "passthru\s{0,$WILDCARD_SHORT}\(" \
    "2_php_passthru.txt" \
    "-i"
    
    search "Dangerous PHP function: escapeshell" \
    'escapeshell' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'escapeshell' \
    "2_php_escapeshell.txt" \
    "-i"
    
    search "Dangerous PHP function: system" \
    'system(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "system\s{0,$WILDCARD_SHORT}\(" \
    "2_php_system.txt" \
    "-i"
    
    search "Dangerous PHP function: fopen" \
    'fopen(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "fopen\s{0,$WILDCARD_SHORT}\(" \
    "2_php_fopen.txt" \
    "-i"
    
    search "Dangerous PHP function: file_get_contents" \
    'file_get_contents (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "file_get_contents\s{0,$WILDCARD_SHORT}\(" \
    "3_php_file_get_contents.txt" \
    "-i"
    
    search "Dangerous PHP function: imagecreatefrom" \
    'imagecreatefrom' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'imagecreatefrom' \
    "3_php_imagecreatefrom.txt" \
    "-i"
    
    search "Dangerous PHP function: mkdir" \
    'mkdir (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "mkdir\s{0,$WILDCARD_SHORT}\(" \
    "2_php_mkdir.txt" \
    "-i"
    
    search "Dangerous PHP function: chmod" \
    'chmod (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "chmod\s{0,$WILDCARD_SHORT}\(" \
    "2_php_chmod.txt" \
    "-i"
    
    search "Dangerous PHP function: chown" \
    'chown (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "chown\s{0,$WILDCARD_SHORT}\(" \
    "2_php_chown.txt" \
    "-i"
    
    search "Dangerous PHP function: file" \
    'file (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "file\s{0,$WILDCARD_SHORT}\(" \
    "2_php_file.txt" \
    "-i"
    
    search "Dangerous PHP function: link" \
    'link (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "link\s{0,$WILDCARD_SHORT}\(" \
    "2_php_link.txt" \
    "-i"
    
    search "Dangerous PHP function: rmdir" \
    'rmdir (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "rmdir\s{0,$WILDCARD_SHORT}\(" \
    "2_php_rmdir.txt" \
    "-i"
    
    search "CURLOPT_SSL_VERIFYPEER should be set to TRUE, CURLOPT_SSL_VERIFYHOST should be set to 2, if there is a mixup, this can go really wrong. See https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html" \
    'CURLOPT_SSL_VERIFYPEER' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'CURLOPT_SSL_VERIFYPEER' \
    "1_php_verifypeer-verifypeer.txt" \
    "-i"
    
    search "CURLOPT_SSL_VERIFYPEER should be set to TRUE, CURLOPT_SSL_VERIFYHOST should be set to 2, if there is a mixup, this can go really wrong. See https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html" \
    'CURLOPT_SSL_VERIFYHOST' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'CURLOPT_SSL_VERIFYHOST' \
    "1_php_verifypeer-verifyhost.txt" \
    "-i"
    
    search "gnutls_certificate_verify_peers, see https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html" \
    'gnutls_certificate_verify_peers' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'gnutls_certificate_verify_peers' \
    "1_php_gnutls-certificate-verify-peers.txt" \
    "-i"
    
    search "fsockopen is not checking server certificates if used with a ssl:// URL. See https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html" \
    'fsockopen (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "fsockopen\s{0,$WILDCARD_SHORT}\(" \
    "1_php_fsockopen.txt" \
    "-i"
    
    search "You can make a lot of things wrong with include" \
    'include (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "include\s{0,$WILDCARD_SHORT}\(" \
    "2_php_include.txt" \
    "-i"
    
    search "You can make a lot of things wrong with include_once" \
    'include_once (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "include_once\s{0,$WILDCARD_SHORT}\(" \
    "2_php_include_once.txt" \
    "-i"
    
    search "You can make a lot of things wrong with require" \
    'require (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "require\s{0,$WILDCARD_SHORT}\(" \
    "2_php_require.txt" \
    "-i"
    
    search "You can make a lot of things wrong with require_once" \
    'require_once (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "require_once\s{0,$WILDCARD_SHORT}\(" \
    "2_php_require_once.txt" \
    "-i"
    
    search "Methods that often introduce XSS: echo" \
    'echo' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "echo" \
    "4_php_echo_high_volume.txt" \
    "-i"
    
    search "Methods that often introduce XSS: echo in combination with \$_POST." \
    'echo $_POST["ABC"]' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "echo.{0,$WILDCARD_LONG}\$_POST" \
    "1_php_echo_low_volume_POST.txt" \
    "-i"
    
    search "Methods that often introduce XSS: echo in combination with \$_GET." \
    'echo $_GET["ABC"]' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "echo.{0,$WILDCARD_LONG}\$_GET" \
    "1_php_echo_low_volume_GET.txt" \
    "-i"
    
    search "Methods that often introduce XSS: echo in combination with \$_COOKIE. And there is no good explanation usually why a cookie is printed to the HTML anyway (debug interface?)." \
    'echo $_COOKIE["ABC"]' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "echo.{0,$WILDCARD_LONG}\$_COOKIE" \
    "1_php_echo_low_volume_COOKIE.txt" \
    "-i"
    
    search "Methods that often introduce XSS: echo in combination with \$_REQUEST." \
    'echo $_REQUEST["ABC"]' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "echo.{0,$WILDCARD_LONG}\$_REQUEST" \
    "1_php_echo_low_volume_REQUEST.txt" \
    "-i"
    
    search "Methods that often introduce XSS: print" \
    'print' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "print" \
    "4_php_print_high_volume.txt" \
    "-i"
    
    search "Methods that often introduce XSS: print in combination with \$_POST." \
    'print $_POST["ABC"]' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "print.{0,$WILDCARD_LONG}\$_POST" \
    "1_php_print_low_volume_POST.txt" \
    "-i"
    
    search "Methods that often introduce XSS: print in combination with \$_GET." \
    'print $_GET["ABC"]' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "print.{0,$WILDCARD_LONG}\$_GET" \
    "1_php_print_low_volume_GET.txt" \
    "-i"
    
    search "Methods that often introduce XSS: print in combination with \$_COOKIE. And there is no good explanation usually why a cookie is printed to the HTML anyway (debug interface?)." \
    'print $_COOKIE["ABC"]' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "print.{0,$WILDCARD_LONG}\$_COOKIE" \
    "1_php_print_low_volume_COOKIE.txt" \
    "-i"
    
    search "Methods that often introduce XSS: print in combination with \$_REQUEST. Don't use \$_REQUEST in general." \
    'print $_REQUEST["ABC"]' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "print.{0,$WILDCARD_LONG}\$_REQUEST" \
    "1_php_print_low_volume_REQUEST.txt" \
    "-i"
    
    search "Databases in PHP: pg_query" \
    'pg_query(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "pg_query\s{0,$WILDCARD_SHORT}\(" \
    "3_php_sql_pg_query.txt" \
    "-i"
    
    search "Databases in PHP: mysqli_" \
    'mysqli_method(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "mysqli_.{1,$WILDCARD_SHORT}\(" \
    "3_php_sql_mysqli.txt" \
    "-i"
    
    search "Databases in PHP: mysql_" \
    'mysql_method(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "mysql_.{1,$WILDCARD_SHORT}\(" \
    "3_php_sql_mysql.txt" \
    "-i"
    
    search "Databases in PHP: mssql_" \
    'mssql_method(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "mssql_.{1,$WILDCARD_SHORT}\(" \
    "3_php_sql_mssql.txt" \
    "-i"
    
    search "Databases in PHP: odbc_exec" \
    'odbc_exec(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "odbc_exec\s{0,$WILDCARD_SHORT}\(" \
    "3_php_sql_odbc_exec.txt" \
    "-i"
    
    search "PHP rand(): This is not a secure random." \
    'rand(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "rand\s{0,$WILDCARD_SHORT}\(" \
    "3_php_rand.txt" \
    "-i"
    
    search "Extract can be dangerous and could be used as backdoor, see http://blog.sucuri.net/2014/02/php-backdoors-hidden-with-clever-use-of-extract-function.html#null" \
    'extract(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "extract\s{0,$WILDCARD_SHORT}\(" \
    "3_php_extract.txt" \
    "-i"
    
    search "Assert can be used as backdoor, see http://rileykidd.com/2013/08/21/the-backdoor-you-didnt-grep/" \
    'assert(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "assert\s{0,$WILDCARD_SHORT}\(" \
    "3_php_assert.txt" \
    "-i"
    
    search "Preg_replace can be used as backdoor, see http://labs.sucuri.net/?note=2012-05-21" \
    'preg_replace(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "preg_replace\s{0,$WILDCARD_SHORT}\(" \
    "3_php_preg_replace.txt" \
    "-i"
    
    search "The big problem with == is that in PHP (and some other languages), this comparison is not type safe. What you should always use is ===. For example a hash value that starts with 0E could be interpreted as an integer if you don't take care. There were real world bugs exploiting this issue already, think login form and comparing the hashed user password, what happens if you type in 0 as the password and brute force different usernames until a user has a hash which starts with 0E?" \
    'hashvalue_from_db == PBKDF2(password_from_login_http_request)' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "[^=]==[^=]" \
    "4_php_type_unsafe_comparison.txt"
fi


#The HTML specific stuff
if [ "$DO_HTML" = "true" ]; then
    
    echo "#Doing HTML"
    
    search "HTML upload." \
    'enctype="multipart/form-data"' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "multipart/form-data" \
    "2_html_upload_form_tag.txt" \
    "-i"
    
    search "HTML upload form." \
    '<input name="param" type="file"' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "type=.?file" \
    "3_html_upload_input_tag.txt" \
    "-i"
    
    search "Autocomplete should be set to off for password fields." \
    'autocomplete' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'autocomplete' \
    "5_html_autocomplete.txt" \
    "-i"
    
    search "Angular.js has this Strict Contextual Escaping (SCE) that should prevent ." \
    '$sceProvider.enabled(false)' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'sceProvider\.enabled\(' \
    "3_angularjs_sceprovider_enabled.txt" \
    "-i"
    
    search 'From the Angular.js explanation for Strict Contextual Escaping (SCE): You can then audit your code (a simple grep would do) to ensure that this is only done for those values that you can easily tell are safe - because they were received from your server, sanitized by your library, etc. [...] In the case of AngularJS SCE service, one uses {@link ng.$sce#trustAs $sce.trustAs} (and shorthand methods such as {@link ng.$sce#trustAsHtml $sce.trustAsHtml}, etc.) to obtain values that will be accepted by SCE / privileged contexts.' \
    '$sce.trustAsHtml' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'sce\.trustAs' \
    "3_angularjs_sceprovider_check_all_instances_of_unsafe_html_1.txt" \
    "-i"
    
    search 'From the Angular.js explanation for Strict Contextual Escaping (SCE): You can then audit your code (a simple grep would do) to ensure that this is only done for those values that you can easily tell are safe - because they were received from your server, sanitized by your library, etc. [...] In the case of AngularJS SCE service, one uses {@link ng.$sce#trustAs $sce.trustAs} (and shorthand methods such as {@link ng.$sce#trustAsHtml $sce.trustAsHtml}, etc.) to obtain values that will be accepted by SCE / privileged contexts.' \
    'ng.$sce#trustAs' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'sce#trustAs' \
    "3_angularjs_sceprovider_check_all_instances_of_unsafe_html_2.txt" \
    "-i"
    
fi


#JavaScript specific stuff
if [ "$DO_JAVASCRIPT" = "true" ]; then
    
    echo "#Doing JavaScript"
    
    search "Location hash: DOM-based XSS source/sink." \
    'location.hash' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'location\.hash' \
    "4_general_dom_xss_location-hash.txt"
    
    search "Location href: DOM-based XSS source/sink." \
    'location.href' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'location\.href' \
    "4_general_dom_xss_location-href.txt"
    
    search "Location pathname: DOM-based XSS source/sink." \
    'location.pathname' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'location\.pathname' \
    "4_general_dom_xss_location-pathname.txt"
    
    search "Location search: DOM-based XSS source/sink." \
    'location.search' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'location\.search' \
    "4_general_dom_xss_location-search.txt"
    
    search "appendChild: DOM-based XSS sink." \
    '.appendChild(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.appendChild\(' \
    "4_general_dom_xss_appendChild.txt"
    
    search "Document location: DOM-based XSS source/sink." \
    'document.location' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'document\.location' \
    "4_general_dom_xss_document_location.txt"
    
    search "Window location: DOM-based XSS source/sink." \
    'window.location' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'window\.location' \
    "4_general_dom_xss_window-location.txt"
    
    search "Document referrer: DOM-based XSS source/sink." \
    'document.referrer' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'document\.referrer' \
    "4_general_dom_xss_document-referrer.txt"
    
    search "Document URL: DOM-based XSS source/sink." \
    'document.URL' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'document\.URL' \
    "4_general_dom_xss_document-URL.txt"
    
    search "Document Write and variants of it: DOM-based XSS source/sink." \
    'document.writeln(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'document\.writel?n?\(' \
    "4_general_dom_xss_document-write.txt"
    
    search "InnerHTML: DOM-based XSS source/sink." \
    '.innerHTML =' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.innerHTML\s{0,$WILDCARD_SHORT}=" \
    "4_general_dom_xss_innerHTML.txt"
    
    search "OuterHTML: DOM-based XSS source/sink." \
    '.outerHTML =' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\.outerHTML\s{0,$WILDCARD_SHORT}=" \
    "4_general_dom_xss_outerHTML.txt"

fi


if [ "$DO_MODSECURITY" = "true" ]; then
    
    echo "#Doing modsecurity"
    
    search "Block is not recommended to use because it is depending on default action, use deny (or allow)" \
    'block' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'block' \
    "3_modsecurity_block.txt" \
    "-i"
    
    search "Rather complex modsecurity constructs that are worth having a look." \
    'ctl:auditEngine' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'ctl:auditEngine' \
    "3_modsecurity_ctl_auditEngine.txt" \
    "-i"
    
    search "Rather complex modsecurity constructs that are worth having a look." \
    'ctl:ruleEngine' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'ctl:ruleEngine' \
    "3_modsecurity_ctl_ruleEngine.txt" \
    "-i"
    
    search "Rather complex modsecurity constructs that are worth having a look." \
    'ctl:ruleRemoveById' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'ctl:ruleRemoveById' \
    "3_modsecurity_ctl_ruleRemoveById.txt" \
    "-i"
    
    search "Possible command injection when executing bash scripts." \
    'exec:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'exec:' \
    "4_modsecurity_exec.txt" \
    "-i"
    
    search "Modsecurity actively changing HTTP response content." \
    'append:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'append:' \
    "4_modsecurity_append.txt" \
    "-i"
    
    search "Modsecurity actively changing HTTP response content." \
    'SecContentInjection' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'SecContentInjection' \
    "4_modsecurity_SecContentInjection.txt" \
    "-i"
    
    #Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
    search "Modsecurity inspecting uploaded files." \
    '@inspectFile' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '@inspectFile' \
    "4_modsecurity_inspectFile.txt" \
    "-i"
    
    search "Modsecurity audit configuration information." \
    'SecAuditEngine' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'SecAuditEngine' \
    "4_modsecurity_SecAuditEngine.txt" \
    "-i"
    
    search "Modsecurity audit configuration information." \
    'SecAuditLogParts' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'SecAuditLogParts' \
    "4_modsecurity_SecAuditLogParts.txt" \
    "-i"
    
fi


#mobile device stuff
if [ "$DO_MOBILE" = "true" ]; then
    
    echo "#Doing mobile"
    
    search "Root detection." \
    'root detection' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "root.{0,$WILDCARD_SHORT}detection" \
    "2_general_mobile_root_detection_root-detection.txt" \
    "-i"
    
    search "Root detection." \
    'root device' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "root.{0,$WILDCARD_SHORT}Device" \
    "2_general_mobile_root_detection_root-device.txt" \
    "-i"
    
    search "Root detection." \
    'isRooted' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "is.{0,$WILDCARD_SHORT}rooted" \
    "2_general_mobile_root_detection_isRooted.txt" \
    "-i"
    
    search "Root detection." \
    'detect root' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "detect.{0,$WILDCARD_SHORT}root" \
    "2_general_mobile_root_detection_detectRoot.txt" \
    "-i"
    
    search "Jailbreak." \
    'jail_break' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "jail.{0,$WILDCARD_SHORT}break" \
    "2_general_mobile_jailbreak.txt" \
    "-i"
    
    search "Superuser. Sometimes the root user of *nix is referenced, sometimes it is about root detection on mobile phones (e.g. Android Superuser.apk app detection)" \
    'super_user' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "super.{0,$WILDCARD_SHORT}user" \
    "2_general_superuser.txt" \
    "-i"
    
    search "Su and sudo binary and variants of it" \
    'sudo binary' \
    'suite.api.java.rql.construct.Binary, super(name, contentType, binary' \
    "su.{0,$WILDCARD_LONG}binary" \
    "2_general_su-binary.txt" \
    "-i"
fi


#The Android specific stuff
if [ "$DO_ANDROID" = "true" ]; then
    #For interesting inputs see:
    # http://developer.android.com/training/articles/security-tips.html
    # http://source.android.com/devices/tech/security/
    
    echo "#Doing Android"
    
    search "printStackTrace logs to Android log, information leakage, etc." \
    '.printStackTrace(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.printStackTrace\(' \
    "3_android_printStackTrace.txt"
    
    search "From http://developer.android.com/reference/android/util/Log.html : The order in terms of verbosity, from least to most is ERROR, WARN, INFO, DEBUG, VERBOSE. Verbose should never be compiled into an application except during development. Debug logs are compiled in but stripped at runtime. Error, warning and info logs are always kept." \
    'Log.e' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'Log\.e\(' \
    "3_android_logging_error.txt"
    
    search "From http://developer.android.com/reference/android/util/Log.html : The order in terms of verbosity, from least to most is ERROR, WARN, INFO, DEBUG, VERBOSE. Verbose should never be compiled into an application except during development. Debug logs are compiled in but stripped at runtime. Error, warning and info logs are always kept." \
    'Log.w' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'Log\.w\(' \
    "3_android_logging_warning.txt"
    
    search "From http://developer.android.com/reference/android/util/Log.html : The order in terms of verbosity, from least to most is ERROR, WARN, INFO, DEBUG, VERBOSE. Verbose should never be compiled into an application except during development. Debug logs are compiled in but stripped at runtime. Error, warning and info logs are always kept." \
    'Log.i' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'Log\.i\(' \
    "3_android_logging_information.txt"
    
    search "From http://developer.android.com/reference/android/util/Log.html : The order in terms of verbosity, from least to most is ERROR, WARN, INFO, DEBUG, VERBOSE. Verbose should never be compiled into an application except during development. Debug logs are compiled in but stripped at runtime. Error, warning and info logs are always kept." \
    'Log.d' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'Log\.d\(' \
    "3_android_logging_debug.txt"
    
    search "From http://developer.android.com/reference/android/util/Log.html : The order in terms of verbosity, from least to most is ERROR, WARN, INFO, DEBUG, VERBOSE. Verbose should never be compiled into an application except during development. Debug logs are compiled in but stripped at runtime. Error, warning and info logs are always kept." \
    'Log.v' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'Log\.v\(' \
    "3_android_logging_verbose.txt"
    
    search "File MODE_PRIVATE for file access on Android, see https://developer.android.com/reference/android/content/Context.html" \
    'MODE_PRIVATE' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'MODE_PRIVATE' \
    "3_android_access_mode-private.txt"
    
    search "File MODE_WORLD_READABLE for file access on Android, see https://developer.android.com/reference/android/content/Context.html" \
    'MODE_WORLD_READABLE' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'MODE_WORLD_READABLE' \
    "1_android_access_mode-world-readable.txt"
    
    search "File MODE_WORLD_WRITEABLE for file access on Android, see https://developer.android.com/reference/android/content/Context.html" \
    'MODE_WORLD_WRITEABLE' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'MODE_WORLD_WRITEABLE' \
    "1_android_access_mode-world-writeable.txt"
    
    search "Opening files via URI on Android, see https://developer.android.com/reference/android/content/ContentProvider.html#openFile%28android.net.Uri,%20java.lang.String%29" \
    '.openFile(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.openFile\(' \
    "3_android_access_openFile.txt"
    
    search "Opening an asset files on Android, see https://developer.android.com/reference/android/content/ContentProvider.html" \
    '.openAssetFile(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.openAssetFile\(' \
    "3_android_access_openAssetFile.txt"
    
    search "Android database open or create" \
    '.openOrCreate' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.openOrCreate' \
    "3_android_access_openOrCreate.txt"
    
    search "Android get database" \
    '.getDatabase(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.getDatabase\(' \
    "3_android_access_getDatabase.txt"
    
    search "Android open database" \
    '.openDatabase' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.openDatabase\(' \
    "3_android_access_openDatabase.txt"
    
    search "Get shared preferences on Android, see https://developer.android.com/reference/android/content/SharedPreferences.html" \
    '.getShared' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.getShared' \
    "3_android_access_getShared.txt"
    
    search "Get cache directory on Android, see https://developer.android.com/reference/android/content/Context.html" \
    'context.getCacheDir()' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.getCache' \
    "3_android_access_getCache.txt"
    
    search "Get code cache directory on Android, see https://developer.android.com/reference/android/content/Context.html" \
    '.getCodeCache' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.getCodeCache' \
    "3_android_access_getCodeCache.txt"
    
    search "Get external cache directory on Android, see https://developer.android.com/reference/android/content/Context.html" \
    '.getExternalCache' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.getExternalCache' \
    "3_android_access_getExternalCache.txt"
    
    search "Do a query on Android" \
    '.query(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'query\(' \
    "3_android_access_query.txt"
    
    search "RawQuery. If the first argument to rawQuery is a user suplied input, it's an SQL injection." \
    'rawQuery(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'rawQuery\(' \
    "3_android_access_rawQuery.txt"
    
    search "RawQueryWithFactory. If the second argument to rawQueryWithFactory is a user suplied input, it's an SQL injection." \
    'rawQueryWithFactory(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'rawQueryWithFactory\(' \
    "3_android_access_rawQueryWithFactory.txt"
    
    search "Android compile SQL statement" \
    'compileStatement(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'compileStatement\(' \
    "3_android_access_compileStatement.txt"
    
    search "Registering receivers and sending broadcasts can be dangerous when exported. See http://resources.infosecinstitute.com/android-hacking-security-part-3-exploiting-broadcast-receivers/" \
    'android:exported=true' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "android:exported.{0,$WILDCARD_SHORT}true" \
    "3_android_intents_intent-filter_exported.txt" \
    "-i"
    
    search "Registering receivers and sending broadcasts can be dangerous when exported. See http://resources.infosecinstitute.com/android-hacking-security-part-3-exploiting-broadcast-receivers/" \
    'registerReceiver(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "registerReceiver\(" \
    "3_android_intents_intent-filter_registerReceiver.txt" \
    "-i"
    
    search "Registering receivers and sending broadcasts can be dangerous when exported. See http://resources.infosecinstitute.com/android-hacking-security-part-3-exploiting-broadcast-receivers/" \
    'sendBroadcast(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "sendBroadcast\(" \
    "3_android_intents_intent-filter_sendBroadcast.txt" \
    "-i"
    
    search "Android get intent" \
    '.getIntent(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.getIntent\(' \
    "3_android_intents_getIntent.txt"
    
    search "Android get data from an intent" \
    '.getData(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.getData\(' \
    "3_android_intents_getData.txt"
    
    search "Android get info about running processes" \
    'RunningAppProcessInfo' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'RunningAppProcessInfo' \
    "3_android_intents_RunningAppProcessInfo.txt"
    
    search "Methods to overwrite SSL certificate checks." \
    'X509TrustManager' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'X509TrustManager' \
    "2_android_ssl_x509TrustManager.txt"
    
    search "Android get a key store" \
    'KeyStore' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'KeyStore' \
    "2_android_ssl_keyStorage.txt"
    
    search "Insecure hostname verification." \
    'ALLOW_ALL_HOSTNAME_VERIFIER' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'ALLOW_ALL_HOSTNAME_VERIFIER' \
    "1_android_ssl_hostname_verifier.txt"
    
    search "Implementation of SSL trust settings." \
    'implements TrustStrategy' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'implements TrustStrategy' \
    "2_android_ssl_trustStrategy.txt"
    
    search "Used to query other appps or let them query, see http://developer.android.com/guide/topics/providers/content-provider-basics.html" \
    'ContentResolver' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'ContentResolver' \
    "3_android_contentResolver.txt"
    
    search "Debuggable webview, see https://developer.chrome.com/devtools/docs/remote-debugging#debugging-webviews" \
    '.setWebContentsDebuggingEnabled(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\.setWebContentsDebuggingEnabled\(' \
    "1_android_setWebContentsDebuggingEnabled.txt"
    
    search "CheckServerTrusted, often used for certificate pinning on Android" \
    'checkServerTrusted(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "checkServerTrusted\(" \
    "3_android_checkServerTrusted.txt"
    
    search "If an Android app wants to specify how the app is backuped, you use BackupAgent to interfere... Often shows which sensitive data is not written to the backup. See https://developer.android.com/reference/android/app/backup/BackupAgent.html" \
    'new BackupAgent()' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "BackupAgent" \
    "3_android_backupAgent.txt"
fi


#The iOS specific stuff
if [ "$DO_IOS" = "true" ]; then
    
    echo "#Doing iOS"
    
    search "iOS File protection APIs" \
    'NSFileProtection' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'NSFileProtection' \
    "3_ios_file_access_nsfileprotection.txt"
    
    search "iOS File protection APIs" \
    'NSFileManager' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'NSFileManager' \
    "3_ios_file_access_nsfilemanager.txt"
    
    search "iOS File protection APIs" \
    'NSPersistantStoreCoordinator' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'NSPersistantStoreCoordinator' \
    "3_ios_file_access_nspersistantstorecoordinator.txt"
    
    search "iOS File protection APIs" \
    'NSData' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'NSData' \
    "3_ios_file_access_nsdata.txt"
    
    search "iOS Keychain stuff" \
    'kSecAttrAccessible' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'kSecAttrAccessible' \
    "3_ios_keychain_ksecattraccessible.txt"
    
    search "iOS Keychain stuff" \
    'SecItemAdd' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'SecItemAdd' \
    "3_ios_keychain_secitemadd.txt"
    
    search "iOS Keychain stuff" \
    'KeychainItemWrapper' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'KeychainItemWrapper' \
    "3_ios_keychain_KeychainItemWrapper.txt"
    
    search "iOS Keychain stuff" \
    'Security.h' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'Security\.h' \
    "3_ios_keychain_security_h.txt"
    
    search "CFBundleURLSchemes" \
    'CFBundleURLSchemes' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'CFBundleURLSchemes' \
    "3_ios_CFBundleURLSchemes.txt"
    
    search "kCFStream" \
    'kCFStream' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'kCFStream' \
    "3_ios_kCFStream.txt"
    
    search "CFFTPStream" \
    'CFFTPStream' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'CFFTPStream' \
    "3_ios_CFFTPStream.txt"
    
    search "CFHTTP" \
    'CFHTTP' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'CFHTTP' \
    "3_ios_CFHTTP.txt"
    
    search "CFNetServices" \
    'CFNetServices' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'CFNetServices' \
    "3_ios_CFNetServices.txt"
    
    search "FTPURL" \
    'FTPURL' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'FTPURL' \
    "3_ios_FTPURL.txt"
    
    search "IOBluetooth" \
    'IOBluetooth' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'IOBluetooth' \
    "3_ios_IOBluetooth.txt"
    
    search "NSLog" \
    'NSLog(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'NSLog\(' \
    "3_ios_NSLog.txt"
    
    search "iOS string format function initWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
    'initWithFormat:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'initWithFormat:' \
    "3_ios_string_format_initWithFormat.txt"
    
    search "iOS string format function informativeTextWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
    'informativeTextWithFormat:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'informativeTextWithFormat:' \
    "3_ios_string_format_informativeTextWithFormat.txt"
    
    search "iOS string format function format. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
    'format:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'format:' \
    "3_ios_string_format_format.txt"
    
    search "iOS string format function stringWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
    'stringWithFormat:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'stringWithFormat:' \
    "3_ios_string_format_stringWithFormat.txt"
    
    search "iOS string format function appendFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
    'appendFormat:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'appendFormat:' \
    "3_ios_string_format_appendFormat.txt"
    
    search "iOS string format function predicateWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
    'predicateWithFormat:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'predicateWithFormat:' \
    "3_ios_string_format_predicateWithFormat.txt"
    
    search "iOS string format function NSRunAlertPanel. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
    'NSRunAlertPanel' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'NSRunAlertPanel' \
    "3_ios_string_format_NSRunAlertPanel.txt"
    
    search "iOS string format function handleOpenURL. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
    'handleOpenURL:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'handleOpenURL:' \
    "3_ios_string_format_url_handler_handleOpenURL.txt"
    
    search "iOS string format function openURL. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
    'openURL:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'openURL:' \
    "3_ios_string_format_url_handler_openURL.txt"

fi


#The C and C-derived languages specific stuff
if [ "$DO_C" = "true" ]; then
    
    echo "#Doing C and derived languages"
    
    search "malloc. Rather rare bug, but see issues CVE-2010-0041 and CVE-2010-0042. Uninitialized memory access issues? Could also happen in java/android native code. Also developers should check return codes." \
    'malloc(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'malloc\(' \
    "4_general_malloc.txt"
    
    search "realloc. Rather rare bug, but see issues CVE-2010-0041 and CVE-2010-0042. Uninitialized memory access issues? Could also happen in java/android native code. Also developers should check return codes." \
    'realloc(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'realloc\(' \
    "4_general_realloc.txt"
    
    search "Buffer overflows and format string vulnerable methods: memcpy, memset, strcat --> strlcat, strcpy --> strlcpy, strncat --> strlcat, strncpy --> strlcpy, sprintf --> snprintf, vsprintf --> vsnprintf, gets --> fgets" \
    'memcpy(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'memcpy\(' \
    "2_general_insecure_c_functions_memcpy.txt"
    
    search "Buffer overflows and format string vulnerable methods: memcpy, memset, strcat --> strlcat, strcpy --> strlcpy, strncat --> strlcat, strncpy --> strlcpy, sprintf --> snprintf, vsprintf --> vsnprintf, gets --> fgets" \
    'memset(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'memset\(' \
    "2_general_insecure_c_functions_memset.txt"
    
    search "Buffer overflows and format string vulnerable methods: memcpy, memset, strcat --> strlcat, strcpy --> strlcpy, strncat --> strlcat, strncpy --> strlcpy, sprintf --> snprintf, vsprintf --> vsnprintf, gets --> fgets" \
    'strncat(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'strn?cat\(' \
    "2_general_insecure_c_functions_strcat_strncat.txt"
    
    search "Buffer overflows and format string vulnerable methods: memcpy, memset, strcat --> strlcat, strcpy --> strlcpy, strncat --> strlcat, strncpy --> strlcpy, sprintf --> snprintf, vsprintf --> vsnprintf, gets --> fgets" \
    'strncpy(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'strn?cpy\(' \
    "2_general_insecure_c_functions_strcpy_strncpy.txt"
    
    search "Buffer overflows and format string vulnerable methods: memcpy, memset, strcat --> strlcat, strcpy --> strlcpy, strncat --> strlcat, strncpy --> strlcpy, sprintf --> snprintf, vsprintf --> vsnprintf, gets --> fgets" \
    'snprintf(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'sn?printf\(' \
    "2_general_insecure_c_functions_sprintf_snprintf.txt"
    
    search "Buffer overflows and format string vulnerable methods: memcpy, memset, strcat --> strlcat, strcpy --> strlcpy, strncat --> strlcat, strncpy --> strlcpy, sprintf --> snprintf, vsprintf --> vsnprintf, gets --> fgets" \
    'fnprintf(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'fn?printf\(' \
    "2_general_insecure_c_functions_fprintf_fnprintf.txt"
    
    search "Buffer overflows and format string vulnerable methods: memcpy, memset, strcat --> strlcat, strcpy --> strlcpy, strncat --> strlcat, strncpy --> strlcpy, sprintf --> snprintf, vsprintf --> vsnprintf, gets --> fgets" \
    'fscanf(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'f?scanf\(' \
    "2_general_insecure_c_functions_fscanf_scanf.txt"
    
    search "Buffer overflows and format string vulnerable methods: memcpy, memset, strcat --> strlcat, strcpy --> strlcpy, strncat --> strlcat, strncpy --> strlcpy, sprintf --> snprintf, vsprintf --> vsnprintf, gets --> fgets" \
    'gets(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '[^a-zA-Z_-]gets\(' \
    "2_general_insecure_c_functions_gets.txt"
    
fi

if [ "$DO_MALWARE_DETECTION" = "true" ]; then
    
    echo "#Doing malware detection"
    
    search "Viagra search" \
    'viagra' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'viagra' \
    "4_malware_viagra.txt" \
    "-i"
    
    search "Potenzmittel is the German word mostly used for viagra" \
    'potenzmittel' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'potenzmittel' \
    "4_malware_potenzmittel.txt" \
    "-i"
    
    search "Pharmacy" \
    'pharmacy' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'pharmacy' \
    "4_malware_pharmacy.txt" \
    "-i"
    
    search "Drug" \
    'drug' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'drug' \
    "4_malware_drug.txt" \
    "-i"
fi

#The crypto and credentials specific stuff (language agnostic)
if [ "$DO_CRYPTO_AND_CREDENTIALS" = "true" ]; then
    
    echo "#Doing crypto and credentials"
    
    search "Crypt (the method itself) can be dangerous, also matches any calls to decrypt(, encrypt( or whatevercrypt(, which is desired" \
    'crypt(' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'crypt\(' \
    "3_general_crypt_call.txt" \
    "-i"
    
    search "Rot32 is really really bad obfuscation and has nothing to do with crypto." \
    'ROT32' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'ROT32' \
    "3_general_ciphers_rot32.txt" \
    "-i"
    
    search "RC2 cipher. Security depends heavily on usage and what is secured." \
    'RC2' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'RC2' \
    "3_general_ciphers_rc2.txt" \
    "-i"
    
    search "RC4 cipher. Security depends heavily on usage and what is secured." \
    'RC4' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'RC4' \
    "3_general_ciphers_rc4.txt"
    
    search "CRC32 is a checksum algorithm. Security depends heavily on usage and what is secured." \
    'CRC32' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'CRC32' \
    "3_general_ciphers_crc32.txt" \
    "-i"
    
    search "DES cipher. Security depends heavily on usage and what is secured." \
    'DES' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'DES' \
    "3_general_ciphers_des.txt"
    
    search "MD2. Security depends heavily on usage and what is secured." \
    'MD2' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'MD2' \
    "3_general_ciphers_md2.txt"
    
    search "MD5. Security depends heavily on usage and what is secured." \
    'MD5' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'MD5' \
    "3_general_ciphers_md5.txt"
    
    search "SHA1. Security depends heavily on usage and what is secured." \
    'SHA1' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'SHA-?1' \
    "3_general_ciphers_sha1_uppercase.txt"
    
    search "SHA1. Security depends heavily on usage and what is secured." \
    'sha1' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'sha-?1' \
    "3_general_ciphers_sha1_lowercase.txt"
    
    search "SHA256. Security depends heavily on usage and what is secured." \
    'SHA256' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'SHA256' \
    "3_general_ciphers_sha256.txt" \
    "-i"
    
    search "SHA256. Security depends heavily on usage and what is secured." \
    'SHA512' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'SHA512' \
    "3_general_ciphers_sha512.txt" \
    "-i"
    
    search "NTLM. Security depends heavily on usage and what is secured." \
    'NTLM' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'NTLM' \
    "3_general_ciphers_ntlm.txt"
    
    search "Kerberos. Security depends heavily on usage and what is secured." \
    'Kerberos' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'kerberos' \
    "3_general_ciphers_kerberos.txt" \
    "-i"
    
    #take care with the next regex, ! has a special meaning in double quoted strings but not in single quoted
    search "Hash" \
    'hash_value' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'hash(?!(table|map|set|code))' \
    "5_general_hash.txt" \
    "-i"
    
    search 'Find *nix passwd or shadow files.' \
    '_xcsbuildagent:*:239:239:Xcode Server Build Agent:/var/empty:/usr/bin/false' \
    '/Users/eh2pasz/workspace/ios/CCB/CCB/Classes/CBSaver.h:23:46: note: passing argument to parameter "name" here^M+ (NSString *)loadStringWithName:(NSString *)name;' \
    "[^:]{1,$WILDCARD_SHORT}:[^:]{1,$WILDCARD_LONG}:\d{0,$WILDCARD_SHORT}:\d{0,$WILDCARD_SHORT}:[^:]{0,$WILDCARD_LONG}:[^:]{0,$WILDCARD_LONG}:" \
    "1_general_passwd_or_shadow_files.txt" \
    "-i"
    
    search "Encryption key and variants of it" \
    'encrypt the key' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "encrypt.{0,$WILDCARD_SHORT}key" \
    "2_general_encryption_key.txt" \
    "-i"
    
    search "Narrow search for certificate and keys specifics of base64 encoded format" \
    'BEGIN CERTIFICATE' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'BEGIN CERTIFICATE' \
    "1_general_certificates_and_keys_narrow_begin-certificate.txt"
    
    search "Narrow search for certificate and keys specifics of base64 encoded format" \
    'PRIVATE KEY' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'PRIVATE KEY' \
    "1_general_certificates_and_keys_narrow_private-key.txt"
    
    search "Narrow search for certificate and keys specifics of base64 encoded format" \
    'PUBLIC KEY' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'PUBLIC KEY' \
    "1_general_certificates_and_keys_narrow_public-key.txt"
    
    search "Wide search for certificate and keys specifics of base64 encoded format" \
    'begin certificate' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "BEGIN.{0,$WILDCARD_SHORT}CERTIFICATE" \
    "4_general_certificates_and_keys_wide_begin-certificate.txt" \
    "-i"
    
    search "Wide search for certificate and keys specifics of base64 encoded format" \
    'private key' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "PRIVATE{0,$WILDCARD_SHORT}KEY" \
    "4_general_certificates_and_keys_wide_private-key.txt" \
    "-i"
    
    search "Wide search for certificate and keys specifics of base64 encoded format" \
    'public key' \
    'public String getBlaKey' \
    "PUBLIC.{0,$WILDCARD_SHORT}KEY" \
    "4_general_certificates_and_keys_wide_public-key.txt" \
    "-i"
    
    search "Salt for a hashing algorithm?" \
    'Salt' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "Salt" \
    "5_general_salt.txt" \
    "-i"
    
    search "Default password" \
    'default-password' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'default.?password' \
    "2_general_default_password.txt" \
    "-i"
    
    search "Password and variants of it" \
    'pass-word or passwd' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'pass.?wo?r?d' \
    "2_general_password.txt" \
    "-i"
    
    search "Credentials. Included everything 'creden' because some programers write credencials instead of credentials and such things." \
    'credentials' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'creden' \
    "3_general_credentials.txt" \
    "-i"
    
    search "Passcode and variants of it" \
    'passcode' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "pass.?code" \
    "3_general_passcode.txt" \
    "-i"
    
    search "Passphrase and variants of it" \
    'passphrase' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "pass.?phrase" \
    "3_general_passphrase.txt" \
    "-i"
    
    search "Secret and variants of it" \
    'secret' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "se?3?cre?3?t" \
    "3_general_secret.txt" \
    "-i"
    
    search "PIN code and variants of it" \
    'pin code' \
    'mapping between error codes, pin.hashCode' \
    "pin.{0,$WILDCARD_SHORT}code" \
    "2_general_pin_code.txt" \
    "-i"
    
    search "Proxy-Authorization" \
    'ProxyAuthorisation' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'Proxy.?Authoris?z?ation' \
    "4_general_proxy-authorization.txt" \
    "-i"
    
    search "Authorization" \
    'Authorisation' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'Authoris?z?ation' \
    "4_general_authorization.txt" \
    "-i"
    
    search "Authentication" \
    'Authentication' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'Authentication' \
    "4_general_authentication.txt" \
    "-i"
    
    search "SSL usage with requireSSL" \
    'requireSSL' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "require.{0,$WILDCARD_SHORT}SSL" \
    "3_general_ssl_usage_require-ssl.txt" \
    "-i"
    
    search "SSL usage with useSSL" \
    'use ssl' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "use.{0,$WILDCARD_SHORT}SSL" \
    "3_general_ssl_usage_use-ssl.txt" \
    "-i"
    
    search "TLS usage with require TLS" \
    'require TLS' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "require.{0,$WILDCARD_SHORT}TLS" \
    "3_general_tls_usage_require-tls.txt" \
    "-i"
    
    search "TLS usage with use TLS" \
    'use TLS' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "use.{0,$WILDCARD_SHORT}TLS" \
    "3_general_tls_usage_use-tls.txt" \
    "-i"
    
fi

#Very general stuff (language agnostic)
if [ "$DO_GENERAL" = "true" ]; then
    
    echo "#Doing general"
    
    search "Exec mostly means executing on OS." \
    'exec (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "exec\s{0,$WILDCARD_SHORT}\(" \
    "3_general_exec.txt"
    
    search "Eval mostly means evaluating commands." \
    'eval (' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "eval\s{0,$WILDCARD_SHORT}\(" \
    "3_general_eval.txt"
    
    search "Session timeouts should be reasonable short for things like sessions for web logins but can also lead to denial of service conditions in other cases." \
    'session-timeout' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'session-?\s?time-?\s?out' \
    "4_general_session_timeout.txt" \
    "-i"
    
    search "General setcookie command used in HTTP, important to see HTTPonly/secure flags, path setting, etc." \
    'setcookie' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'setcookie' \
    "3_general_setcookie.txt" \
    "-i"
    
    search "Relative paths. May allow an attacker to put something early in the search path (if parts are user supplied input) and overwrite behavior" \
    '../../' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\./' \
    "4_general_relative_paths.txt" \
    "-i"
    
    #Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
    search "Email addresses" \
    'example@example.com' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,4}\b' \
    "5_general_email.txt" \
    "-i"
     
    search "TODOs, unfinished and insecure things?" \
    'TODO:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'Todo' \
    "5_general_todo_capital.txt"
    
    search "TODOs, unfinished and insecure things?" \
    'TODO:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'TODO' \
    "5_general_todo_uppercase.txt"
    
    search "Workarounds, maybe they work around security?" \
    'workaround: ' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'workaround' \
    "5_general_workaround.txt" \
    "-i"
    
    search "Hack. Developers sometimes hack a workaround around security." \
    'hack' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'hack' \
    "4_general_hack.txt" \
    "-i"
    
    search "Crack. Sounds suspicious." \
    'crack' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'crack' \
    "4_general_crack.txt" \
    "-i"
    
    search "Exploit and variants of it. Sounds suspicious." \
    'exploit' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'xploit' \
    "4_general_exploit.txt" \
    "-i"
    
    search "Bypass. Sounds suspicious, what do they bypass exactly?" \
    'bypass' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'bypass' \
    "4_general_bypass.txt" \
    "-i"
    
    search "Backdoor. Sounds suspicious, why would anyone ever use this word?" \
    'back-door' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "back.{0,$WILDCARD_SHORT}door" \
    "4_general_backdoor.txt" \
    "-i"
    
    search "Backd00r. Sounds suspicious, why would anyone ever use this word?" \
    'back-d00r' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "back.{0,$WILDCARD_SHORT}d00r" \
    "4_general_backd00r.txt" \
    "-i"
    
    search "Fake. Sounds suspicious." \
    'fake:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'fake' \
    "4_general_fake.txt" \
    "-i"
    
    search "All URIs" \
    'https://example.com' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'https?://' \
    "4_general_https_and_http_urls.txt" \
    "-i"
    
    search "All HTTP URIs" \
    'http://example.com' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'http://' \
    "4_general_http_urls.txt" \
    "-i"
    
    search "Non-SSL URIs" \
    'ftp://example.com' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'ftp://' \
    "3_general_non_ssl_uris_ftp.txt" \
    "-i"
    
    search "Non-SSL URIs" \
    'imap://example.com' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'imap://' \
    "3_general_non_ssl_uris_imap.txt" \
    "-i"
    
    search "Non-SSL URIs" \
    'file://c/example.txt' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'file://' \
    "3_general_non_ssl_uris_file.txt" \
    "-i"
    
    search "Hidden things, for example hidden HTML fields" \
    'hidden:' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'hidden' \
    "4_general_hidden.txt" \
    "-i"
    
    search "Directory listing, usually a bad idea in web servers." \
    'directory-listing' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "directory.{0,$WILDCARD_SHORT}listing" \
    "3_general_directory_listing.txt" \
    "-i"
    
    search "SQL injection and variants of it. Sometimes refered in comments or variable names for code that should prevent it.  If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
    'sql-injection' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "sql.{0,$WILDCARD_SHORT}injection" \
    "2_general_sql_injection.txt" \
    "-i"
    
    search "XSS. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
    'XSS' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'xss' \
    "2_general_xss.txt" \
    "-i"
    
    search "Clickjacking and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
    'click-jacking' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "click.{0,$WILDCARD_SHORT}jacking" \
    "2_general_hacking_techniques_clickjacking.txt" \
    "-i"
    
    search "XSRF/CSRF and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
    'xsrf' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "xsrf" \
    "2_general_hacking_techniques_xsrf.txt" \
    "-i"
    
    search "XSRF/CSRF and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
    'csrf' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "csrf" \
    "2_general_hacking_techniques_csrf.txt" \
    "-i"
    
    search "Buffer overflow and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
    'buffer-overflow' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "buffer.{0,$WILDCARD_SHORT}overflow" \
    "2_general_hacking_techniques_buffer-overflow.txt" \
    "-i"
    
    search "Integer overflow and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
    'integer-overflow' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "integer.{0,$WILDCARD_SHORT}overflow" \
    "2_general_hacking_techniques_integer-overflow.txt" \
    "-i"
    
    search "Obfuscation and variants of it. Might be interesting code where the obfuscation is done. If you find something interesting that is used for obfuscation in a framework, you might want to add another grep for that in this script." \
    'obfuscation' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "obfuscat" \
    "2_general_obfuscation.txt" \
    "-i"
    
    #take care with the following regex, backticks have to be escaped
    search "Everything between backticks, because in Perl and Shell scirpting (eg. cgi-scripts) these are system execs." \
    '`basename file-var`' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "\`.{2,$WILDCARD_LONG}\`" \
    "2_general_backticks.txt"\
    "-i"
    
    search "SQL SELECT statement" \
    'SELECT EXAMPLE, ABC, DEF FROM TABLE' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "SELECT.{0,$WILDCARD_LONG}FROM" \
    "3_general_sql_select.txt" \
    "-i"
    
    search "SQL INSERT statement" \
    'INSER 123 INTO TABLE' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "INSERT.{0,$WILDCARD_LONG}INTO" \
    "3_general_sql_insert.txt" \
    "-i"
    
    search "SQL DELETE statement" \
    'DELETE COLUMN WHERE 1=1' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "DELETE.{0,$WILDCARD_LONG}WHERE" \
    "3_general_sql_delete.txt" \
    "-i"
    
    search "SQL SQLITE" \
    'sqlite' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    "sqlite" \
    "4_general_sql_sqlite.txt" \
    "-i"
    
    search "Base64 encoded data (that is more than 6 bytes long). This regex won't detect a base64 encoded value over several lines..." \
    'YWJj YScqKyo6LV/Dpw==' \
    '/target/ //JQLite - the following ones shouldnt be an issue anymore as we require more than 6 bytes: done echo else gen/ ////' \
    '^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$' \
    "2_general_base64.txt"
    #case sensitive, the regex is insensitive anyway
    
    search "Base64 URL-safe encoded data (that is more than 6 bytes long). To get from URL-safe base64 to regular base64 you need .replace('-','+').replace('_','/'). This regex won't detect a base64 encoded value over several lines..." \
    'YScqKyo6LV_Dpw==' \
    '/target/ //JQLite - the following ones shouldnt be an issue anymore as we require more than 6 bytes: done echo else gen/ ////' \
    '^(?:[A-Za-z0-9\-_]{4})+(?:[A-Za-z0-9\-_]{2}==|[A-Za-z0-9\-_]{3}=|[A-Za-z0-9\-_]{4})$' \
    "2_general_base64.txt"
    #case sensitive, the regex is insensitive anyway
    
    search "GPL violation? Not security related, but your customer might be happy to know such stuff" \
    'GNU GPL' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'GNU\sGPL' \
    "5_general_gpl1.txt" \
    "-i"
    
    search "GPL violation? Not security related, but your customer might be happy to know such stuff" \
    'GPLv2' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'GPLv2' \
    "5_general_gpl2.txt" \
    "-i"
    
    search "GPL violation? Not security related, but your customer might be happy to know such stuff" \
    'GPLv3' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'GPLv3' \
    "5_general_gpl3.txt" \
    "-i"
    
    search "GPL violation? Not security related, but your customer might be happy to know such stuff" \
    'GPL Version' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'GPL\sVersion' \
    "5_general_gpl4.txt" \
    "-i"
    
    search "GPL violation? Not security related, but your customer might be happy to know such stuff" \
    'General Public License' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'General\sPublic\sLicense' \
    "5_general_gpl5.txt" \
    "-i"
    
    search "Stupid: Swear words are often used when things don't work as intended by the developer." \
    'Stupid!' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'stupid' \
    "3_general_swear_stupid.txt" \
    "-i"
    
    search "Fuck: Swear words are often used when things don't work as intended by the developer. X-)" \
    'Fuck!' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'fuck' \
    "3_general_swear_fuck.txt" \
    "-i"
    
    search "Shit and bullshit: Swear words are often used when things don't work as intended by the developer." \
    'Shit!' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'shit' \
    "3_general_swear_shit.txt" \
    "-i"
    
    search "Crap: Swear words are often used when things don't work as intended by the developer." \
    'Crap!' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    'crap' \
    "3_general_swear_crap.txt" \
    "-i"
    
    search "IP addresses" \
    '192.168.0.1 10.0.0.1' \
    'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
    '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' \
    "2_general_ip-addresses.txt" \
    "-i"
    #IP-Adresses
    #\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
    #  (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
    #  (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
    #  (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b

fi

if [ "$BACKGROUND" = "true" ]; then
    echo ""
    echo "We cannot remove empty files because we don't know yet which grep processes already finished (background with & is enabled)."
    echo "Use the following command to see when all greps are done:"
    echo "ps waux|$GREP_COMMAND $GREP_COMMAND"
    echo "Use the following command to delete empty files (if you specified not to write comments...):"
    echo "find $TARGET -type f -size 0 -maxdepth 1 -delete"
fi

echo ""
echo "Done grep. Results in $TARGET."
echo "It's optimised to be viewed with 'less -R $TARGET/*' and then you can hop from one file to the next with :n"
echo "and :p. Maybe you want to add the -S option of less for very long lines. The cat command works fine too. "
echo "If you want another editor you should probably remove --color=always from the options"
echo ""
echo "Have a grepy day."

###
#END CODE SECTION
###