// KerberosAuthentication.cpp : Defines the entry point for the console application.
//

// AW.Eas.Airwatch.Kerberos.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
* Copyright 2009  by the Massachusetts Institute of Technology.
* All Rights Reserved.
*
* Export of this software from the United States of America may
*   require a specific license from the United States Government.
*   It is the responsibility of any person or organization contemplating
*   export to obtain such a license before exporting.
*
* WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
* distribute this software and its documentation for any purpose and
* without fee is hereby granted, provided that the above copyright
* notice appear in all copies and that both that copyright notice and
* this permission notice appear in supporting documentation, and that
* the name of M.I.T. not be used in advertising or publicity pertaining
* to distribution of the software without specific, written prior
* permission.  Furthermore if you modify this software you must label
* your software as modified software and not distribute it in such a
* fashion that it might be confused with the original M.I.T. software.
* M.I.T. makes no representations about the suitability of
* this software for any purpose.  It is provided "as is" without express
* or implied warranty.
*/

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "include/gssapi/gssapi_krb5.h"
#include <stdint.h>
#include <Ws2tcpip.h>

#include "base64.h"
#include<string>
#include<iostream>
using namespace std;

/*
* Test program for protocol transition (S4U2Self) and constrained delegation
* (S4U2Proxy)
*
* Note: because of name canonicalization, the following tips may help
* when configuring with Active Directory:
*
* - Create a computer account FOO$
* - Set the UPN to host/foo.domain (no suffix); this is necessary to
*   be able to send an AS-REQ as this principal, otherwise you would
*   need to use the canonical name (FOO$), which will cause principal
*   comparison errors in gss_accept_sec_context().
* - Add a SPN of host/foo.domain
* - Configure the computer account to support constrained delegation with
*   protocol transition (Trust this computer for delegation to specified
*   services only / Use any authentication protocol)
* - Add host/foo.domain to the keytab (possibly easiest to do this
*   with ktadd)
*
* For S4U2Proxy to work the TGT must be forwardable too.
*
* Usage eg:
*
* kinit -k -t test.keytab -f 'host/test.win.mit.edu@WIN.MIT.EDU'
* ./t_s4u delegtest@WIN.MIT.EDU HOST/WIN-EQ7E4AA2WR8.win.mit.edu@WIN.MIT.EDU test.keytab
*/

char* getErrorMessage(char *m, OM_uint32 code, int type)
{
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx;

	msg_ctx = 0;
	while (1) {
		maj_stat = gss_display_status(&min_stat, code,
			type, GSS_C_NULL_OID,
			&msg_ctx, &msg);
		(void)gss_release_buffer(&min_stat, &msg);

		if (!msg_ctx)
		{
			return (char *)msg.value;
		}
	}
}

char* constrainedDelegate(OM_uint32 *minor,
	gss_OID_set desired_mechs,
	gss_name_t target,
	gss_cred_id_t delegated_cred_handle,
	gss_cred_id_t verifier_cred_handle)
{
	OM_uint32 major, tmp_minor;
	gss_ctx_id_t initiator_context = GSS_C_NO_CONTEXT;
	gss_name_t cred_name = GSS_C_NO_NAME;
	OM_uint32 time_rec, lifetime;
	gss_cred_usage_t usage;
	gss_buffer_desc token;
	gss_OID_set mechs;
	char* majorErrorMessage;
	char* minorErrorMessage;

	if (gss_inquire_cred(minor, verifier_cred_handle, &cred_name,
		&lifetime, &usage, NULL) == GSS_S_COMPLETE) {
		gss_release_name(&tmp_minor, &cred_name);
	}
	if (gss_inquire_cred(minor, delegated_cred_handle, &cred_name,
		&lifetime, &usage, &mechs) == GSS_S_COMPLETE) {
		gss_release_name(&tmp_minor, &cred_name);
	}

	major = gss_init_sec_context(minor,
		delegated_cred_handle,
		&initiator_context,
		target,
		mechs ? &mechs->elements[0] : (gss_OID)gss_mech_krb5,
		GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG,
		GSS_C_INDEFINITE,
		GSS_C_NO_CHANNEL_BINDINGS,
		GSS_C_NO_BUFFER,
		NULL,
		&token,
		NULL,
		&time_rec);
	if (GSS_ERROR(major))
	{
		majorErrorMessage = getErrorMessage("Error: gss_init_sec_context", major, GSS_C_GSS_CODE);
		minorErrorMessage = getErrorMessage("Error: gss_init_sec_context", *minor, GSS_C_MECH_CODE);

		return minorErrorMessage;
	}

	size_t encodedLen = 2048;
	char* encodedToken;
	std::string encodedTokenStr = base64_encode((unsigned char *)token.value, token.length).c_str();

	encodedToken = new char[encodedTokenStr.size() + 1];
	//std::copy(encodedTokenStr.begin(), encodedTokenStr.end(), encodedToken);
	//encodedToken[encodedTokenStr.size()] = '\0';
	encodedTokenStr.copy(encodedToken, encodedTokenStr.length());

	(void)gss_release_buffer(&tmp_minor, &token);
	(void)gss_delete_sec_context(&tmp_minor, &initiator_context, NULL);
	(void)gss_release_oid_set(&tmp_minor, &mechs);

	return encodedToken;
}

int getTGT(char *principal, char *password)
{
	krb5_error_code ret;
	krb5_principal client_princ = NULL;
	krb5_context context;
	krb5_ccache ccache;
	krb5_creds creds;

	//Initialize kerberos5 context for getting TGT
	ret = krb5_init_context(&context);
	if (ret)
	{
		return ret;
	}

	//Create default cache base on kerb ccname in registry(windows)
	ret = krb5_cc_default(context, &ccache);
	if (ret)
	{
		return ret;
	}

	//Initialize credential structure
	memset(&creds, 0, sizeof(creds));

	//Convert principal name(string) into kerb5 principal structure 
	ret = krb5_parse_name(context, principal, &client_princ);
	if (ret)
	{
		return ret;
	}

	//Get TGT according to principal credential 
	ret = krb5_get_init_creds_password(context, &creds, client_princ,
		password, NULL, NULL, 0, NULL, NULL);
	if (ret)
	{
		return ret;
	}

	//Verify TGT
	ret = krb5_verify_init_creds(context, &creds, NULL, NULL, NULL, NULL);
	if (ret)
	{
		return ret;
	}

	//Initialize ccache
	ret = krb5_cc_initialize(context, ccache, client_princ);
	if (ret)
	{
		return ret;
	}

	//Save TGT in ccache
	ret = krb5_cc_store_cred(context, ccache, &creds);
	if (ret)
	{
		return ret;
	}

	return ret;
}

char* GetKerberosToken(char* principal, char* password, char* impersonatedUsername, char* targetSPN)//int argc, char *argv[])
{
	OM_uint32 minor, major;
	//OM_uint32 timeRemain;
	gss_cred_id_t impersonator_cred_handle = GSS_C_NO_CREDENTIAL;
	gss_cred_id_t user_cred_handle = GSS_C_NO_CREDENTIAL;
	gss_cred_id_t delegated_cred_handle = GSS_C_NO_CREDENTIAL;
	gss_name_t user = GSS_C_NO_NAME, target = GSS_C_NO_NAME;
	gss_OID_set_desc mechs;
	gss_OID_set actual_mechs = GSS_C_NO_OID_SET;
	gss_buffer_desc buf;
	char* kerberosToken;
	char* majorErrorMessage;
	char* minorErrorMessage;

	buf.value = impersonatedUsername;
	buf.length = strlen((char *)buf.value);

	//Get impersonated user name
	major = gss_import_name(&minor, &buf,
		(gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
		&user);
	if (GSS_ERROR(major)) {
		majorErrorMessage = getErrorMessage("Error: gss_import_name(user)", major, GSS_C_GSS_CODE);
		minorErrorMessage = getErrorMessage("Error: gss_import_name(user)", minor, GSS_C_MECH_CODE);

		return minorErrorMessage;
	}

	//Get target SPN
	buf.value = targetSPN;
	buf.length = strlen((char *)buf.value);

	major = gss_import_name(&minor, &buf,
		(gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
		&target);
	if (GSS_ERROR(major)) {
		majorErrorMessage = getErrorMessage("Error: gss_import_name(target)", major, GSS_C_GSS_CODE);
		minorErrorMessage = getErrorMessage("Error: gss_import_name(target)", minor, GSS_C_MECH_CODE);

		return minorErrorMessage;
	}

	mechs.elements = (gss_OID)gss_mech_krb5;
	mechs.count = 1;

	/* TODO: get remaining time */
	//Get remaining time here
	//if remaining time less or equal 0, reget TGT
	//if(timeRemain <= 0)
	//	major = getTGT(principal, password);
	//if (GSS_ERROR(major)) {
	//	//displayStatus("Error: gss_acquire_cred", major, minor);

	//	//	//TODO: If TGT has expired, return error message.
	//	majorErrorMessage = getErrorMessage("Error: getTGT", major, GSS_C_GSS_CODE);
	//	minorErrorMessage = getErrorMessage("Error: getTGT", minor, GSS_C_MECH_CODE);
	//	return minorErrorMessage;
	//}

	/* get default cred */
	major = gss_acquire_cred(&minor,
		GSS_C_NO_NAME,
		GSS_C_INDEFINITE,
		&mechs,
		GSS_C_BOTH,
		&impersonator_cred_handle,
		&actual_mechs,
		NULL);
	if (GSS_ERROR(major)) {

		//Create TGT if it can't be got
		major = getTGT(principal, password);
		if (GSS_ERROR(major)) {

			//if recreating TGT failed, return error message.
			majorErrorMessage = getErrorMessage("Error: getTGT", major, GSS_C_GSS_CODE);
			minorErrorMessage = getErrorMessage("Error: getTGT", minor, GSS_C_MECH_CODE);
			return minorErrorMessage;
		}

		major = gss_acquire_cred(&minor,
			GSS_C_NO_NAME,
			GSS_C_INDEFINITE,
			&mechs,
			GSS_C_BOTH,
			&impersonator_cred_handle,
			&actual_mechs,
			NULL);
	}
	if (GSS_ERROR(major)) {

		//if getting TGT failed, return error message.
		majorErrorMessage = getErrorMessage("Error: gss_acquire_cred", major, GSS_C_GSS_CODE);
		minorErrorMessage = getErrorMessage("Error: gss_acquire_cred", minor, GSS_C_MECH_CODE);
		return minorErrorMessage;
	}

	(void)gss_release_oid_set(&minor, &actual_mechs);

	/* get S4U2Self cred */
	major = gss_acquire_cred_impersonate_name(&minor,
		impersonator_cred_handle,
		user,
		GSS_C_INDEFINITE,
		&mechs,
		GSS_C_INITIATE,
		&user_cred_handle,
		&actual_mechs,
		NULL);
	if (GSS_ERROR(major)) {

		//Create TGT if it has expired
		getTGT(principal, password);
		if (GSS_ERROR(major)) {

			//if recreating TGT failed, return error message.
			majorErrorMessage = getErrorMessage("Error: getTGT", major, GSS_C_GSS_CODE);
			minorErrorMessage = getErrorMessage("Error: getTGT", minor, GSS_C_MECH_CODE);
			return minorErrorMessage;
		}

		gss_acquire_cred(&minor,
			GSS_C_NO_NAME,
			GSS_C_INDEFINITE,
			&mechs,
			GSS_C_BOTH,
			&impersonator_cred_handle,
			&actual_mechs,
			NULL);

		major = gss_acquire_cred_impersonate_name(&minor,
			impersonator_cred_handle,
			user,
			GSS_C_INDEFINITE,
			&mechs,
			GSS_C_INITIATE,
			&user_cred_handle,
			&actual_mechs,
			NULL);

		if (GSS_ERROR(major)) {

			//if getting service ticket failed, return error message
			majorErrorMessage = getErrorMessage("Error: gss_acquire_cred_impersonate_name", major, GSS_C_GSS_CODE);
			minorErrorMessage = getErrorMessage("Error: gss_acquire_cred_impersonate_name", minor, GSS_C_MECH_CODE);
			return minorErrorMessage;
		}
	}

	/* kft */
	delegated_cred_handle = user_cred_handle;

	if (target != GSS_C_NO_NAME &&
		delegated_cred_handle != GSS_C_NO_CREDENTIAL) {
		kerberosToken = constrainedDelegate(&minor, &mechs, target,
			delegated_cred_handle,
			impersonator_cred_handle);
	}
	else if (target != GSS_C_NO_NAME) {

		//if getting kerberos token failed, return error message
		majorErrorMessage = getErrorMessage("Error: get kerberos token", major, GSS_C_GSS_CODE);
		minorErrorMessage = getErrorMessage("Error: get kerberos token", minor, GSS_C_MECH_CODE);
		return minorErrorMessage;
	}

	return kerberosToken;
}

int _tmain(int argc, _TCHAR* argv[])
{
	char* principal="1", *password="1", *impersonatedUsername="1", *targetSPN="1";
	string kerberosToken = GetKerberosToken(principal, password, impersonatedUsername, targetSPN);
	cout << kerberosToken << endl;
	return 0;
}