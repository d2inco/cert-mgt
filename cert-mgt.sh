#!/bin/bash
#
# Program:      cert-mgt.sh
# Author:	David Dee
# Date: 	07 Nov 2020
# Purpose:	Manage creation/update of CA and Certificates for
#		self-managed domains.

# I referenced:
#   https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/
#   https://www.simba.com/products/SEN/doc/Client-Server_user_guide/content/clientserver/configuringssl/signingca.htm
# command reference:
#   https://www.sslshopper.com/article-most-common-openssl-commands.html


set -u


######################################################################
# Declarations
######################################################################
# {{{1

BASENAME="`basename $0`"
LOCKFILE=/var/tmp/${BASENAME}.lock
# Or to limit on a per-user basis, not system wide:
# LOCKFILE=/var/tmp/${BASENAME}-${USER}.lock
SILENT=0
VERBOSE=0
DEBUG=0

CREATE_CA=0
CREATE_CERT=""
ADDONLIST=""

# Declare DOMAINS and ADDONS before reading the .conf file
DOMAINS=()
SANS=()

. cert-mgt.conf

# }}}1
######################################################################
# Constants
######################################################################
# {{{1

# dont set a password on the P12 file
P12PASSWORD=""

if [ -f /usr/bin/openssl11 ]; then
    OPENSSLBIN=/usr/bin/openssl11
else
    OPENSSLBIN=/usr/bin/openssl
fi

# }}}1
######################################################################
#  Functions
######################################################################
# {{{1





usage() {			# {{{2

    echo " Usage:"
    echo "     $0 [-xvs]"
    echo "        [--create-ca]"
    echo "        [--create-cert ( <FQDN> | all ) [--add-on '<FQDNLIST>' ]]"
    echo ""
    echo "       -s                Silent Mode"
    echo "       -v                Verbose Mode"
    echo "       -x                Debug Mode"
    echo ""

}				# }}}2

cleanup_and_exit() {		# {{{2
    rm -f $LOCKFILE
    exit $1
}				# }}}2

# }}}1
######################################################################
#  Initialization Code
######################################################################
# {{{1

    TEMP=`getopt \
		    -o svxZ: \
		    --long create-ca,create-cert:,add-on: \
		    --long silent,verbose,debug \
	    -n "$0" -- "$@"`

    if [ $? != 0 ] ; then usage; echo "Terminating..." >&2 ; exit 1 ; fi

    # Note the quotes around `$TEMP': they are essential!
    eval set -- "$TEMP"

    while true ; do
	    case "$1" in
		    --create-ca)		CREATE_CA=1; shift ;;
		    --create-cert)		CREATE_CERT="$2"; shift 2 ;;
		    --add-on)			ADDONLIST="$2"; shift 2 ;;
		    -s|--silent)		SILENT=1; shift ;;
		    -v|--verbose)		VERBOSE=$[ $VERBOSE + 1 ]; shift ;;
		    -x|--debug) 		DEBUG=$[ $DEBUG + 1 ]; shift ;;
		       --param1)		PARAM1=$2; shift 2 ;;
		    --)				shift; break ;;
		    *)				usage; exit 1 ;;
	    esac
    done

    # create LOCKFILE; exit if already exists

    /usr/bin/lockfile -3 -r 1 $LOCKFILE
    LOCKSTATUS=$?
    if [ $LOCKSTATUS != 0 ]; then
	echo LOCKSTATUS: $LOCKSTATUS
	echo "Could not create lockfile, $LOCKFILE .  Already exists.  Exiting."
	    PIDOF="`/sbin/pidof -x -o $$ -o %PPID $BASENAME | sed -e 's/ /,/g'`"
	    if [ "$PIDOF" != "" ]; then
		echo ps u -p"$PIDOF"
		     ps u -p"$PIDOF"
		exit 1
	    else
		echo "Not finding a running process of $BASENAME.  There should be at least one, right?"
		echo "Removing the lock file now"
		cleanup_and_exit 1
	    fi
    fi


# }}}1
######################################################################
#  Main Code
######################################################################
# {{{1

    if [ $CREATE_CA -eq 1 ]; then
	echo "Creating CA *Key* and *Root Certificate*"

	read -s -p "New CA Cert's PassPhrase: " CAPHRASE
	read -s -p "                  Verify: " VERIFY
	if [ "$CAPHRASE" != "$VERIFY" ]; then
	    echo "Phrases did not match.  Will not continue."
	    cleanup_and_exit 1
	fi

	if [ -f ${CA_PRIV_KEY} ]; then
	    echo "CA Private Key already exists: ${CA_PRIV_KEY}"
	else
	    ${OPENSSLBIN} genrsa -des3 -out ${CA_PRIV_KEY} \
		    -passout "pass:${CAPHRASE}" \
		    2048
	fi

	if [ -f ${CA_ROOT_CERT} ]; then
	    echo "CA Root Cert already exists: ${CA_ROOT_CERT}"
	else
	    echo "CERT-MGT: creating signed root certificate"

	    SUBJECT=$( printf "/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s" "$COUNTRY" \
			"$STATE" "$LOCALITY" "ORG" "$ORG_UNIT" "$COMMON_NAME" \
			"$EMAIL" \
			)
	    echo "Subject: $SUBJECT"

	    ${OPENSSLBIN} req -x509 -new -nodes -key ${CA_PRIV_KEY} -sha256 \
		    -days ${ROOT_CERT_VALIDITY_DAYS} -out ${CA_ROOT_CERT} \
		    -subj "$SUBJECT" \
		    -passin "pass:${CAPHRASE}"

	    echo "----------------------------------------------------------------------"
	    echo "CERT-MGT: creating related .p12 certificate"
	    ${OPENSSLBIN} pkcs12 -export \
			    -in ${CA_ROOT_CERT} \
			    -inkey ${CA_PRIV_KEY} \
			    -out ${CA_ROOT_P12} \
			    -passin "pass:${CAPHRASE}" \
			    -passout "pass:${P12PASSWORD}"
	fi

    elif [ "$CREATE_CERT" != "" ]; then

	if [ ! -f ${CA_PRIV_KEY} \
	  -o ! -f ${CA_ROOT_CERT} \
	  -o ! -f ${CA_ROOT_P12} \
	   ]; then
	    echo "Some (or all) of your Certificate Authority (CA) keys don't exist:"
	    echo "     ${CA_PRIV_KEY}"
	    echo "     ${CA_ROOT_CERT}"
	    echo "     ${CA_ROOT_P12}"
	    echo "Please create them with:"
	    echo "    $0 --create-ca"
	    echo ""
	    cleanup_and_exit 0
	fi

	read -s -p "Your CA Cert's PassPhrase: " CAPHRASE

	echo ""

	if [ "$CREATE_CERT" != "all" ]; then
	    DOMAINS=("$CREATE_CERT")
	    SANS=("$ADDONLIST")
	fi

	for i
	in ${!DOMAINS[@]}; do
	    printf "%3d  Domain: %-20s   SANs: '%s'\n" "$i" "${DOMAINS[$i]}" "${SANS[$i]}"

	    DOMAIN="${DOMAINS[$i]}"
	    ADDON="${SANS[$i]}"

	    if [ "$DOMAIN" != "" ]; then

		KEYFILE="${DOMAIN}.key"
		CERTFILE="${DOMAIN}.crt"
		P12FILE="${DOMAIN}.p12"

		if [ ! -f ${KEYFILE} \
		  -o ! -f ${CERTFILE} \
		  -o ! -f ${P12FILE} \
		    ]; then

		    SUBJECT=$( printf "/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s" "$COUNTRY" \
				"$STATE" "$LOCALITY" "ORG" "$ORG_UNIT" "$DOMAIN" \
				"$EMAIL" \
				)

		    echo ""
		    echo "CERT-MGT: creating server key: ${DOMAIN} (encrypted and plaintext)"
		    ${OPENSSLBIN} genrsa -des3 -out ${KEYFILE}-pass -passout "pass:temppass"
		    ${OPENSSLBIN} rsa -in ${KEYFILE}-pass -out ${KEYFILE} -passin "pass:temppass"
		    rm ${KEYFILE}-pass


		    echo "----------------------------------------------------------------------"
		    echo "CERT-MGT: creating signing request"
		    if [ "$ADDON" != "" ]; then
			SAN=$( for D in ${ADDON}; do echo -n "DNS:${D},"; done )
			SAN=${SAN:0:-1}
			echo "SAN: $SAN"
			${OPENSSLBIN} req -new -key ${KEYFILE} -out signingReq.csr \
				-nodes \
				-subj "${SUBJECT}" \
				-addext "subjectAltName=${SAN}"
		    else
			${OPENSSLBIN} req -new -key ${KEYFILE} -out signingReq.csr \
				-nodes \
				-subj "${SUBJECT}"
		    fi

		    if [ ! -f signingReq.csr ]; then
			echo "Stopping - signingReq.csr does not exist after creating it."
			cleanup_and_exit 1
		    fi

		    echo "---- verifying the CSR:"
		    ${OPENSSLBIN} req -text -noout -in signingReq.csr | egrep 'DNS:|Extension|Alternative|Subject:'

		    echo "----------------------------------------------------------------------"
		    echo "CERT-MGT: creating signed certificate"
		    if [ "$ADDON" != "" ]; then
			${OPENSSLBIN} x509 -req -days 365 -in signingReq.csr \
				    -sha256 \
				    -CA ${CA_ROOT_CERT} -CAkey ${CA_PRIV_KEY} -CAcreateserial \
				    -extfile <( echo "subjectAltName=${SAN}" ) \
				    -days ${HOST_CERT_VALIDITY_DAYS} \
				    -out ${CERTFILE} \
				    -passin "pass:${CAPHRASE}"
		    else
			${OPENSSLBIN} x509 -req -days 365 -in signingReq.csr \
				    -sha256 \
				    -CA ${CA_ROOT_CERT} -CAkey ${CA_PRIV_KEY} -CAcreateserial \
				    -days ${HOST_CERT_VALIDITY_DAYS} \
				    -out ${CERTFILE} \
				    -passin "pass:${CAPHRASE}"
		    fi

		    /bin/rm signingReq.csr

		    if [ ! -s ${CERTFILE} ]; then
			echo "Certificate file, ${CERTFILE}, was not created correctly.  Exiting."
			cleanup_and_exit 1
		    fi


		    echo "----------------------------------------------------------------------"
		    echo "CERT-MGT: creating related .p12 certificate"
		    ${OPENSSLBIN} pkcs12 -export \
				    -in ${CERTFILE} \
				    -inkey ${KEYFILE} \
				    -out ${P12FILE} \
				    -certfile ${CA_ROOT_CERT} \
				    -passout "pass:${P12PASSWORD}"

		else
		    echo "All Certificate files for ${DOMAIN} exist; no need to remake them."
		    echo "----------------------------------------------------------------------"
		fi
	    else
		echo "(nothing to do for this one)"
		echo "----------------------------------------------------------------------"
	    fi

	done

    else
	echo "No work requested."
    fi

    ######################################################################

    echo -e "----------------------------------------------------------------------"
    printf "Our CA Key File:         %s\n" "$CA_PRIV_KEY"
    printf "                         (Keep this file protected)\n"
    printf "Our CA Root Cert File:   %s\n" "$CA_ROOT_CERT"
    printf "                         (Distribute to systems)\n"


# }}}1
######################################################################
#  Cleanup Code
######################################################################
# {{{1

    cleanup_and_exit 0

# }}}1
######################################################################
# vim:foldmethod=marker sw=4
