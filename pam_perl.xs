#define PERL_NO_GET_CONTEXT	/* we want efficiency */
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <security/_pam_types.h>

#define _PAM_EXTERN_FUNCTIONS
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>
#include "const.h"


#define XSRETURN_QV(s,v)	STMT_START { XST_mQV( 0,s,v); XSRETURN(1); } STMT_END
#define XSRETURN_QV2(v,c)	STMT_START { XST_mQV2(0,v,c); XSRETURN(1); } STMT_END

#define PUSHq(v,p,l)		mXPUSHs(newSVqvn(p,l,v))

#define XST_mQV(i,s,v)		(ST(i) = sv_2mortal(newSVqv(s,v)))
#define XST_mQV2(i,v,c)		(ST(i) = sv_2mortal(newSVqv2(v,c)))
#define XST_mQVn(i,s,l,v)	(ST(i) = sv_2mortal(newSVqvn(s,l,v)))

#define newSVqv(s,v)		P_newSVqv(aTHX_ s,v)
#define newSVqvn(s,l,v)		P_newSVqvn(aTHX_ s,l,v)
#define newSVqv2(v,c)		P_newSVqv2(aTHX_ v,c)
#define sv_setqvn(a,b,c,d)	P_sv_setqvn(aTHX_ a,b,c,d)

typedef struct {
	PerlInterpreter *perl;
	SV* handle;
	void (*delay_fn)(int retval, unsigned usec_delay, void *appdata_ptr);
	const struct pam_conv *pam_conv;
} datag;
typedef struct {
	pam_handle_t* pamh;
	HV* hv;
} pam_handle_x;
//typedef int xint;
#define xint int

#ifdef TEST_FAST_LOAD
XS(boot_dummy);
//XS(XS_Authen__PAM__Module_conv);
//XS(XS_Authen__PAM__Module_tie);
#endif
XS(boot_Authen__PAM__Module);
SV* P_newSVqv(pTHX_ const char* s, int i);
SV* P_newSVqv2(pTHX_ int i, const char* (*func)(int i,int* len));
SV* Q_intorconst(pTHX_ SV* s);
EXTERN_C void xs_init (pTHX);
EXTERN_C void boot_DynaLoader (pTHX_ CV* cv);
EXTERN_C void boot_Authen__PAM__Module (pTHX_ CV* cv);
void cleanup(__attribute__((unused)) pam_handle_t* pamh, datag* me, __attribute__((unused)) int error_status);

int pam_sm_all(char* func,	pam_handle_t *pamh, int flags, int argc, const char **argv);
#ifdef PAM_SM_AUTH
	int pam_sm_authenticate(	pam_handle_t *pamh, int flags, int argc, const char **argv){return pam_sm_all("authenticate",	pamh,flags,argc,argv);}
	int pam_sm_setcred(		pam_handle_t *pamh, int flags, int argc, const char **argv){return pam_sm_all("setcred",	pamh,flags,argc,argv);}
#endif
#ifdef PAM_SM_ACCOUNT
	int pam_sm_acct_mgmt(		pam_handle_t *pamh, int flags, int argc, const char **argv){return pam_sm_all("acct_mgmt",	pamh,flags,argc,argv);}
#endif
#ifdef PAM_SM_SESSION
	int pam_sm_open_session(	pam_handle_t *pamh, int flags, int argc, const char **argv){return pam_sm_all("open_session",	pamh,flags,argc,argv);}
	int pam_sm_close_session(	pam_handle_t *pamh, int flags, int argc, const char **argv){return pam_sm_all("close_session",	pamh,flags,argc,argv);}
#endif
#ifdef PAM_SM_PASSWORD
	int pam_sm_chauthtok(		pam_handle_t *pamh, int flags, int argc, const char **argv){return pam_sm_all("chauthtok",	pamh,flags,argc,argv);}
#endif

#ifdef PAM_STATIC
	struct pam_module _pam_perl_modstruct = {"pam_perl",
# ifdef PAM_SM_AUTH
		pam_sm_authenticate, pam_sm_setcred,
# else
		NULL, NULL,
# endif
# ifdef PAM_SM_ACCOUNT
		pam_sm_acct_mgmt,
# else
		NULL,
# endif
# ifdef PAM_SM_SESSION
		pam_sm_open_session, pam_sm_close_session,
# else
		NULL, NULL,
# endif
# ifdef PAM_SM_PASSWORD
		pam_sm_chauthtok
# else
		NULL,
# endif
	};
#endif

#define my_perl ((*me).perl)
int pam_sm_all(char* func, pam_handle_t *pamh, int flags, int argc, const char **argv){
	int stat,i,count,ret;
	char *embedding[] = {"", "-e", "0"};
	char *class;
	int embedc=3;
	SV* ret_SV;
	datag *me;

	if(argc >1) return PAM_SYSTEM_ERR; // first arg is relitave package name. If we don't have it, abort.
	class=malloc(strlen(argv[0])+22); // 22 is sizeof base module name in next line +1 for null
	strcpy(class,"Authen::PAM::Module::");
	strcpy(class+21,argv[0]); // 21 is sizeof base module name in previous line without +1 for null
	stat = pam_get_data(pamh,class,(void *)&me); // expected to fail on first call
	if(stat == PAM_NO_MODULE_DATA){		     // becouse it has not been defined yet.
		me = calloc(1,sizeof(datag));
		stat = pam_set_data(pamh,class,me,(void (*)(pam_handle_t *, void *, int))&cleanup);
		if(stat != PAM_SUCCESS){
			printf("debug1\n");
			return stat;
		}
		PERL_SYS_INIT(&embedc,(char ***)&embedding);
		(*me).perl = perl_alloc();
		perl_construct((*me).perl);
		PL_origalen = 1;
		//perl_parse((*me).perl, boot_Authen__PAM__Module, embedc, embedding, (char **)NULL);
		perl_parse((*me).perl, xs_init, embedc, embedding, (char **)NULL);
		load_module(PERL_LOADMOD_NOIMPORT,sv_2mortal(newSVpv(class, 19)),NULL,NULL); // cheating a little here to save memory, perl truncates string to base module name.
		load_module(PERL_LOADMOD_NOIMPORT,sv_2mortal(newSVpv(class, 0)),NULL,NULL); // 0 length tells perl to use strlen.
		PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
		dSP;
		ENTER;
		SAVETMPS;
		PUSHMARK(SP);
		XPUSHs(sv_2mortal(newSVpv(class, 0)));
		XPUSHs(sv_2mortal(sv_setref_pv(newSV(0), "Authen::PAM::Module::_pamh", (void*)pamh)));
		XPUSHs(sv_2mortal(sv_setref_pv(newSV(0), "Authen::PAM::Module::_me",   (void*)me)));
		XPUSHs(sv_2mortal(newSViv(flags)));
		for(i=0;i<argc;i++){
			XPUSHs(sv_2mortal(newSVpv(argv[i], 0)));
		}
		PUTBACK;
		count=call_method("new",G_SCALAR);
		SPAGAIN;
		if(count !=1 ) return PAM_SYSTEM_ERR;
		(*me).handle = newSVsv(POPs);
		PUTBACK;
		FREETMPS;
		LEAVE;
	}else if(stat != PAM_SUCCESS){
		printf("debug2\n");
		return stat;
	}
	free(class);
	dSP;
	ENTER;
	SAVETMPS;
	PUSHMARK(SP);
	XPUSHs((*me).handle);
	XPUSHs(sv_2mortal(newSViv(flags)));
	for(i=0;i<argc;i++) XPUSHs(sv_2mortal(newSVpv(argv[i], 0)));
	PUTBACK;
	count=call_method(func,G_SCALAR);
	SPAGAIN;
	if(count !=1 ) return PAM_SYSTEM_ERR;
	ret_SV=newSVsv(POPs);
	if(SvIOK(ret_SV)){
		ret=SvIVX(sv_2mortal(ret_SV));
	}else if(SvNIOK(ret_SV)){
		ret=SvIV(ret_SV);
	}else{
		ret=SvIV(Q_intorconst(aTHX_ ret_SV));
	}
	PUTBACK;
	FREETMPS;
	LEAVE;
	return ret;
}
void cleanup(__attribute__((unused)) pam_handle_t* pamh, datag* me, __attribute__((unused)) int error_status){
	if((*me).handle)SvREFCNT_dec((*me).handle);
	if((*me).perl){
		perl_destruct((*me).perl);
		perl_free((*me).perl);
		PERL_SYS_TERM();
	}
	free(me);
}
#undef my_perl

EXTERN_C void xs_init(pTHX){
	char *file = __FILE__;
	dXSUB_SYS;

	/* don't double load myself */
#ifdef TEST_FAST_LOAD
	newXS("Authen::PAM::Module::bootstrap", boot_dummy, file);
	boot_Authen__PAM__Module(aTHX_ get_cv("Authen::PAM::Module::bootstrap", GV_ADD));
#else
	newXS("Authen::PAM::Module::bootstrap", boot_Authen__PAM__Module, file);
#endif
	/* load known modules */
	/* DynaLoader is a special case */
	newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, file);
}
#ifdef TEST_FAST_LOAD
XS(boot_dummy){
}
#endif

void P_sv_setqvn(pTHX_ SV* m, int i, const char* s, STRLEN len){
	sv_setpvn(m,s,len);
	SvIV_set(m,i);
	SvPOK_on(m);
}
SV* P_newSVqv2(pTHX_ int i, const char* (*func)(int i,int* len)){
	int len;
	const char* s=(*func)(i,&len);
	SV* m=newSVpv(s,len);
	sv_setiv(m,i);
	SvPOK_on(m);
	return m;
}
SV* P_newSVqvn(pTHX_ const char* s, STRLEN len, int i){
	SV* m=newSVpv(s,len);
	sv_setiv(m,i);
	SvPOK_on(m);
	return m;
}
SV* P_newSVqv(pTHX_ const char* s, int i){
	SV* m=newSVpv(s,strlen(s));
	sv_setiv(m,i);
	SvPOK_on(m);
	return m;
}

SV* Q_intorconst(pTHX_ SV* s){
	int count;
	SV* m;

	dSP;

	//ENTER;
	//SAVETMPS;

	PUSHMARK(SP);
	XPUSHs(s);
	PUTBACK;

	count=call_pv("Authen::PAM::Module::intorconst", G_SCALAR);

	SPAGAIN;

	if (count != 1) croak("Big trouble\n");

	m=POPs;

	PUTBACK;
	//FREETMPS;
	//LEAVE;
	return m;
}

#include "const.c.inc"
#include "const-c.inc"

MODULE = Authen::PAM::Module		PACKAGE = Authen::PAM::Module::_user

void
FETCH(handle)
	pam_handle_x handle
	PROTOTYPE: $;
	PREINIT:
		const char* user;
		int ret;
	CODE:
		ret=pam_get_user(handle.pamh, &user, SvPVX(*(hv_fetch(handle.hv,"user_prompt",11,0))));
		if(ret != PAM_SUCCESS) XSRETURN_QV2(ret, &QContext_ret);
		XSRETURN_PV(user);


#MODULE = Authen::PAM::Module		PACKAGE = Authen::PAM::Module::_env
#
MODULE = Authen::PAM::Module		PACKAGE = Authen::PAM::Module::_item

void
FETCH(pamh, item_type)
	pam_handle_x* pamh=NULL;
	xint item_type
	PROTOTYPE: $$;
    PREINIT:
	const void *item;
	int ret;
    PPCODE:
	ret=pam_get_item((*pamh).pamh, item_type, &item);
	if(ret != PAM_SUCCESS) XSRETURN_QV2(ret, &QContext_ret);
	if(item_type == PAM_FAIL_DELAY){
		datag *me;
		SV** tmp = hv_fetch((*pamh).hv,"me",2,0);
		me = INT2PTR(datag*, SvIV((SV*)SvRV(*tmp)));
		(*me).delay_fn=item;
		XSRETURN_QV("PAM_SUCCESS",PAM_SUCCESS);
	}
	if(item_type == PAM_CONV){
		datag *me;
		SV** tmp = hv_fetch((*pamh).hv,"me",2,0);
		me = INT2PTR(datag*, SvIV((SV*)SvRV(*tmp)));
		(*me).pam_conv=item;
		XSRETURN_QV("PAM_SUCCESS",PAM_SUCCESS);
	}
	XSRETURN_PV((char*)item);

MODULE = Authen::PAM::Module		PACKAGE = Authen::PAM::Module		PREFIX = pam_

void
tie(class,parent)
	SV* class
	SV* parent
	PROTOTYPE: $$;
	CODE:
		ST(0) = sv_bless(newRV_inc(newSVsv(parent)),gv_stashsv(class, GV_ADD));
		XSRETURN(1);

int
pam_set_item(pamh, item_type, item)
	pam_handle_t *pamh
	xint item_type
	const char * item
	PROTOTYPE: $$$;
	INIT:
		if(item_type == PAM_CONV) XSRETURN_QV("PAM_BAD_ITEM",PAM_BAD_ITEM);
		if(item_type == PAM_FAIL_DELAY) XSRETURN_QV("PAM_BAD_ITEM",PAM_BAD_ITEM);

void
conv(handle, ...)
	pam_handle_x handle;
	PROTOTYPE: $@;
	PREINIT:
		struct pam_message** msg=NULL;
		struct pam_response** resp=NULL;
		datag *me;
		int ret, i, j;
	PPCODE:
		msg=calloc(items+1,sizeof(void*));
		*msg=calloc(items+1,sizeof(struct pam_message));
		for(i=1,j=0;i<items;i++,j++){
			if(j)msg[j]=msg[j-1]+1/*sizeof(struct pam_message)*/;
			if(SvTYPE(ST(i))==SVt_RV){
				if(SvTYPE(SvRV(ST(i)))==SVt_PVHV){
					HV* a=(HV*)SvRV(ST(i));
					SV** b=hv_fetch(a,"msg_style",3,0);
					if(b==NULL) croak("null dref");
					(*(msg[j])).msg_style=SvIV(Q_intorconst(aTHX_ *b));
					b=hv_fetch(a,"msg",3,0);
					if(b==NULL) croak("null dref");
					(*(msg[j])).msg=SvPVX(*b);
				}else if(SvTYPE(SvRV(ST(i)))==SVt_PVAV){
					AV* a=(AV*)SvRV(ST(i));
					SV** b=av_fetch(a,0,0);
					if(b==NULL) croak("null dref");
					(*(msg[j])).msg_style=SvIV(Q_intorconst(aTHX_ *b));
					b=av_fetch(a,1,0);
					if(b==NULL) croak("null dref");
					(*(msg[j])).msg=SvPVX(*b);
				}else{
					printf("debug  %d %d\n",i,SvTYPE(SvRV(ST(i))));
					croak("msg is not array or hash");
				}
			}else if(SvTYPE(ST(i))==SVt_PVHV){
				HV* a=(HV*)ST(i);
				SV** b=hv_fetch(a,"msg_style",3,0);
				if(b==NULL) croak("null dref");
				(*(msg[j])).msg_style=SvIV(Q_intorconst(aTHX_ *b));
				b=hv_fetch(a,"msg",3,0);
				if(b==NULL) croak("null dref");
				(*(msg[j])).msg=SvPVX(*b);
			}else if(SvTYPE(ST(i))==SVt_PVAV){
				AV* a=(AV*)ST(i);
				SV** b=av_fetch(a,0,0);
				if(b==NULL) croak("null dref");
				(*(msg[j])).msg_style=SvIV(Q_intorconst(aTHX_ *b));
				b=av_fetch(a,1,0);
				if(b==NULL) croak("null dref");
				(*(msg[j])).msg=SvPVX(*b);
			}else{
				printf("debug %d %d\n",i,SvTYPE(ST(i)));
				croak("msg is not array or hash");
			}
		}
		resp=calloc(items-1,sizeof(void*));
		*resp=calloc(items-1,sizeof(struct pam_response));
		for(i=1,j=0;i<items;i++,j++){
			if(j)resp[j]=resp[0]+1/*sizeof(struct pam_response)*/;
		}
		SV** tmp2 = hv_fetch(handle.hv,"me",2,0);
		me = INT2PTR(datag*, SvIV((SV*)SvRV(*tmp2)));
		if((*me).pam_conv==NULL){
			ret=pam_get_item(handle.pamh, PAM_CONV, (const void**)(&((*me).pam_conv)));
			if(ret != PAM_SUCCESS) XSRETURN_QV2(ret, &QContext_ret);
		}
		ret = (*((*(*me).pam_conv).conv))(items-1, (const struct pam_message **)msg, resp, (*(*me).pam_conv).appdata_ptr);
		if(ret != PAM_SUCCESS) XSRETURN_QV2(ret, &QContext_ret);
		for(i=1,j=0;i<items;i++,j++){
			if(((*resp)[j]).resp){
				XPUSHs(sv_2mortal(newSVqv(((*resp)[j]).resp,((*resp)[j]).resp_retcode)));
				free((*resp[j]).resp);
			}else{
				XPUSHs(sv_2mortal(newSVqv("NULL",((*resp)[j]).resp_retcode)));
			}
		}
		free(resp[0]);
		free(msg[0]);
		free(resp);
		free(msg);


int
pam_putenv(pamh, name_value)
	pam_handle_t *pamh;
	const char *name_value;
	PROTOTYPE: $$;

const char *
pam_getenv(pamh, name)
	pam_handle_t *pamh
	const char * name
	PROTOTYPE: $$;

void
pam_getenvlist(pamh)
	pam_handle_t *pamh
	PROTOTYPE: $;
    PREINIT:
	char ** env;
	int i;
    PPCODE:
	env=pam_getenvlist(pamh);
	for(i=0;env[i];i++){
		XPUSHs(sv_2mortal(newSVpv(env[i],strlen(env[i]))));
	}

const char *
pam_strerror(pamh, errnum)
	pam_handle_t *pamh
	int errnum
	PROTOTYPE: $$;

int
pam_fail_delay(pamh, usec)
	pam_handle_t *pamh
	unsigned int usec
	PROTOTYPE: $$;

INCLUDE: const-xs.inc
INCLUDE: const.xs.inc

BOOT:
	newXSproto("Authen::PAM::Module::_user::TIESCALAR",	XS_Authen__PAM__Module_tie, file, "$$;");
	newXSproto("Authen::PAM::Module::_out::TIEHANDLE",	XS_Authen__PAM__Module_tie, file, "$$;");
	newXSproto("Authen::PAM::Module::_err::TIEHANDLE",	XS_Authen__PAM__Module_tie, file, "$$;");
	newXSproto("Authen::PAM::Module::_item::TIEHASH",	XS_Authen__PAM__Module_tie, file, "$$;");
	newXSproto("Authen::PAM::Module::_env::TIEHASH",	XS_Authen__PAM__Module_tie, file, "$$;");
