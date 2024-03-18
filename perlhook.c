#include <stdio.h>
#include <EXTERN.h>               /* from the Perl distribution     */
#include <perl.h>                 /* from the Perl distribution     */
#include <XSUB.h>

#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

extern short modified;

static PerlInterpreter	*my_perl;  /***    The Perl interpreter    ***/
/*struct hv		*h = NULL;*/
struct ip		*cur_ip;	// current IP header
union {
  void			*cur_ip_end;	// end of IP header (start of next hdr)
  struct tcphdr		*cur_tcp;
  struct udphdr		*cur_udp;
}
// prototypes of utility functions
void pu_make_hdr(void);
void pu_update_hdr(void);
// some perl defines
#ifndef pTHX
  #define pTHX  void
#endif
#ifndef pTHX_
  #define pTHX_
#endif
// -------------------------------------------------------------------
// ph_get_body(): return body of the current packet in string
EXTERN_C void ph_get_body(pTHX_ CV* cv){
  short ofs;
  dXSARGS;
#ifdef WITH_PERL56
  dXSTARG;
#else
  dTARGET;
#endif
  if (items == 0) { EXTEND(SP, 1); }
#ifdef WITH_PERL56
  XSprePUSH;
#endif
  switch (cur_ip->ip_p) {
    case IPPROTO_TCP:
      ofs = (cur_ip->ip_hl<<2) + (cur_tcp->th_off<<2);
      break;
    default:
      ofs = (cur_ip->ip_hl<<2);
  }
  PUSHp( (char*)cur_ip + ofs, ntohs(cur_ip->ip_len)-ofs );
  XSRETURN(1);
}
// -------------------------------------------------------------------
// ph_update_hdr(): update header from %pkt hash values
EXTERN_C void ph_update_hdr(pTHX_ CV* cv){
  struct hv *h;
  struct sv *s;
  short ofs;
  STRLEN len;
  char  *buf;
  struct in_addr addr;
  dXSARGS;
#ifdef WITH_PERL56
  dXSTARG;
#else
  dTARGET;
#endif
  pu_update_hdr();
  XSRETURN(0);
}
// -------------------------------------------------------------------
EXTERN_C voidxs_init(pTHX){
  char *file = __FILE__;
  newXS("get_body", ph_get_body, file);
  newXS("update_hdr", ph_update_hdr, file);
  /*
  newXS("src_ips", my_src_ips, file);
  newXS("src_ipa", my_src_ipa, file);
  newXS("dst_ips", my_dst_ips, file);
  newXS("dst_ipa", my_dst_ipa, file);
  newXS("src_port", my_src_port, file);
  newXS("dst_port", my_dst_port, file);
  */
}
// -------------------------------------------------------------------
// pu_make_hdr(): makes hash %pkt with headers of the current packet
void pu_make_hdr(void) {
  struct hv*		h;

  h = perl_get_hv("pkt", TRUE);
  if (h != NULL) {
    hv_store(h, "src", 3, newSVpv(inet_ntoa(ip->ip_src), 0), 0);
    hv_store(h, "dst", 3, newSVpv(inet_ntoa(ip->ip_dst), 0), 0);
    hv_store(h, "p", 1, newSViv(ip->ip_p), 0);
    hv_store(h, "len", 3, newSViv( ntohs(ip->ip_len) ), 0);
    hv_store(h, "tos", 3, newSViv(ip->ip_tos), 0);
    hv_store(h, "id", 2, newSViv( ntohs(ip->ip_id) ), 0);
    hv_store(h, "ttl", 3, newSViv(ip->ip_ttl), 0);
    switch (ip->ip_p) {
      case IPPROTO_TCP:
        hv_store(h, "sport", 5, newSViv( ntohs(cur_tcp->th_sport) ), 0);
        hv_store(h, "dport", 5, newSViv( ntohs(cur_tcp->th_dport) ), 0);
        hv_store(h, "flags", 5, newSViv(cur_tcp->th_flags), 0);
	hv_store(h, "off", 3, newSViv(cur_tcp->th_off), 0);
        break;
    }
  }
}
// -------------------------------------------------------------------
// pu_update_hdr(): updates current packet header with %pkt values
void pu_update_hdr(void) {
  struct hv		*h;

  h = perl_get_hv("pkt", FALSE);
  if (h != NULL) {
    // src
    if ( (s = *hv_fetch(h, "src", 3, 0)) != NULL )
      if ( inet_pton(AF_INET, buf = SvPV(s, len), &addr) == 1 ) cur_ip->ip_src = addr;
    // dst
    if ( (s = *hv_fetch(h, "dst", 3, 0)) != NULL )
      if ( inet_pton(AF_INET, buf = SvPV(s, len), &addr) == 1 ) cur_ip->ip_dst = addr;
    // ports
    switch (cur_ip->ip_p) {
      case IPPROTO_TCP:
        if ( (s = *hv_fetch(h, "sport", 5, 0)) != NULL )
	  cur_tcp->th_sport = htons(SvIV(s));
        if ( (s = *hv_fetch(h, "dport", 5, 0)) != NULL )
	  cur_tcp->th_dport = htons(SvIV(s));
	break;
    }
  }
  modified = 1;
}
// -------------------------------------------------------------------
void perl_exec(struct ip *ip) {
  cur_ip = ip;
  cur_ip_end = ((char*)ip + (ip->ip_hl<<2));
/*
  cur_tcp = NULL;
  switch (ip->ip_p) {
    case IPPROTO_TCP:
      cur_tcp = (struct tcphdr*) ((char*)ip + (ip->ip_hl<<2));
      break;
  }
*/
  perl_run(my_perl);
}
// -------------------------------------------------------------------
int perl_init(char *name){
  struct { char pv; char *pn; }
    protos[] = {
      { IPPROTO_ICMP, "ICMP" },
      { IPPROTO_IGMP, "IGMP" },
      { IPPROTO_TCP,  "TCP"  },
      { IPPROTO_UDP,  "UDP"  }
    };
  struct sv*		sv;
  struct hv*		h1, h2;
  char *args[2] = { "", name };
  int i;
  my_perl = perl_alloc();
  if (my_perl == NULL) return 0;
  perl_construct(my_perl);
  i = perl_parse(my_perl, xs_init, 2, args, (char **)NULL);
  if (!i) return 0;
  // create global variables
  h1 = perl_get_hv("PROTO", TRUE); SvREADONLY(h1);
  for (i = 0; i < 4; i++) {
    if ( (sv = get_sv(protos[i].pn, TRUE)) != NULL ) { 
      sv_setiv(sv, protos[i].pv); SvREADONLY_on(sv);
      hv_store(h1, protos[i].pn, sv, 0);
      SvREFCNT_inc(sv);
    }
  }
/*
  perl_eval_pv(
    "*ICMP=\\1; *IGMP=\\2; *TCP=\\6; *UDP=\\17;\n"
    "%PROTO = ($ICMP=>'ICMP', $IGMP=>'IGMP', $TCP=>'TCP', $UDP=>'UDP');"
    ,1); */
  return 1;
}
// -------------------------------------------------------------------
void perl_done() {
  perl_destruct(my_perl);
  perl_free(my_perl);
}
// -------------------------------------------------------------------
