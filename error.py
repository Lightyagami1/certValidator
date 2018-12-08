#IP address used to validate is not present in SAN
CERTIFICATE_ERROR_IP_NOT_IN_SAN         = 80002
#DNS name used to validate is not present in SAN
CERTIFICATE_ERROR_DNS_NOT_IN_SAN        = 80003
#IP address used to validate but is present but in wrong SAN key
#also indicates that a dns name based validation might work.
CERTIFICATE_ERROR_IP_IN_WRONG_KEY       = 80004
#current date is before cert not before date
CERTIFICATE_ERROR_DATE_NOT_YET_VALID    = 80005
#current date is after cert not after date
CERTIFICATE_ERROR_DATE_EXPIRED          = 80006
#DNS name does not match CN and there are no SAN entries
CERTIFICATE_ERROR_DNS_DOES_NOT_MATCH_CN = 80007
#cert end constant - fix ssl read cert issue
ERROR_FILE_INVALID                      = 1006
#file at path invalid
ERROR_FILE_NOT_FOUND                    = 2
#file missing at given path
ERROR_INVALID_PARAMETER                 = 87

ERROR_INVALID_NAME                      = 123
