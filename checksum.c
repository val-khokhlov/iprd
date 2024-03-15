#include <sys/types.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
// ====================================================================
// from: tcpdump/print-ip.c
u_short in_cksum(const u_short *addr, register int len, u_short csum) {
	int nleft = len;
	const u_short *w = addr;
	u_short answer;
	int sum = csum;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
		sum += htons(*(u_char *)w<<8);

	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}
// ====================================================================
// from: tcpdump/print-tcp.c
int tcp_cksum(register const struct ip *ip,
		     register const struct tcphdr *tp,
		     register int len)
{
	int i, tlen;
	union phu {
		struct phdr {
			u_int32_t src;
			u_int32_t dst;
			u_char mbz;
			u_char proto;
			u_int16_t len;
		} ph;
		u_int16_t pa[6];
	} phu;
	register const u_int16_t *sp;
	u_int32_t sum;
	tlen = ntohs(ip->ip_len) - ((const char *)tp-(const char*)ip);

	/* pseudo-header.. */
	phu.ph.len = htons(tlen);
	phu.ph.mbz = 0;
	phu.ph.proto = IPPROTO_TCP;
	memcpy(&phu.ph.src, &ip->ip_src.s_addr, sizeof(u_int32_t));
	memcpy(&phu.ph.dst, &ip->ip_dst.s_addr, sizeof(u_int32_t));

	sp = &phu.pa[0];
	sum = sp[0]+sp[1]+sp[2]+sp[3]+sp[4]+sp[5];

	sp = (const u_int16_t *)tp;

	for (i=0; i<(tlen&~1); i+= 2)
		sum += *sp++;

	if (tlen & 1) {
		sum += htons( (*(const u_int8_t *)sp) << 8);
	}

	while (sum > 0xffff)
		sum = (sum & 0xffff) + (sum >> 16);
	sum = ~sum & 0xffff;

	return (sum);
}
