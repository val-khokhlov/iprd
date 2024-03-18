#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <machine/in_cksum.h>

#define	VERSION	"iprd: IP rewrite daemon ver.0.01a, Copyright (C) val khokhlov, 2002"
#define USAGE	"Usage: iprd [-f perl_file] [-d] [-l log_file] [-p pid_file] [-h] [-v]"

int 			sock;			// in/out socket
int			sending = -1;		// out socket while sending
char 			pbuf[IP_MAXPACKET];	// packet buffer
short			plen;			// packet length
enum { INPUT, OUTPUT }	pdir;			// direction
short			modified;		// modified flag
struct sockaddr_in 	addr;			// addr in socket
short			port = 9999;		// port to bind
char			buf[1024];		// misc buffer

short			verbose = 0;		// write debug info?
time_t			shutdown_req;		// shutdown request time
FILE			*LOG = NULL;		// log file
FILE			*PID = NULL;		// pid file
char			*log_file = "/var/log/iprd.log";
char			*pid_file = "/var/run/iprd.pid";
char			*perl_file = NULL;	// perl script to run

void do_rewrite(struct ip *ip);			// rewrite function
static void sigterm_handler(int);		// SIGTERM handler
// checksum functions (checksums.c)
extern int tcp_cksum(register const struct ip *ip,
		     register const struct tcphdr *tp,
		     register int len);
#ifdef WITH_PERL
// perl functions (perlhook.c)
extern int  perl_init(char *name);
extern void perl_exec();
extern void perl_done();
#endif

// ====================================================================
int dprintf(char const *fmt, ...) {
  int			ret = 0;
  va_list		ap;
  char			buf[16];
  time_t		ct;

  if (!verbose) return 0;

  if (LOG != NULL) {
    ct = time(NULL);
    strftime(buf, 16, "%b %e %T", localtime(&ct));
    ret += fprintf(LOG, "%s ", buf);
  }
  
  va_start(ap, fmt);
  ret += vfprintf(LOG != NULL ? LOG : stdout, fmt, ap);
  va_end(ap);
  fflush(LOG);
  return (ret);
}
// ====================================================================
char *print_packet(char *buf, struct ip *ip) {
  struct tcphdr		*tcphdr;
  struct udphdr		*udphdr;
  struct icmp		*icmphdr;
  char			src[20], dst[20];
  int			c = 0;
  // get addresses in readable form
  strcpy(src, (char *)inet_ntoa(ip->ip_src));
  strcpy(dst, (char *)inet_ntoa(ip->ip_dst));
  c += sprintf(buf+c, (pdir == OUTPUT) ? "Out " : "In ");
  switch (ip->ip_p) {
    // TCP
    case IPPROTO_TCP:
      tcphdr = (struct tcphdr*) ((char*)ip + (ip->ip_hl<<2));
      c += sprintf(buf+c, "[TCP] %s:%d -> %s:%d", src, ntohs(tcphdr->th_sport), dst, ntohs(tcphdr->th_dport));
      break;
    // UDP
    case IPPROTO_UDP:
      udphdr = (struct udphdr*) ((char*)ip + (ip->ip_hl<<2));
      c += sprintf(buf+c, "[UDP] %s:%d -> %s:%d", src, ntohs(udphdr->uh_sport), dst, ntohs(udphdr->uh_dport));
      break;
    // ICMP
    case IPPROTO_ICMP:
      icmphdr = (struct icmp*) ((char*)ip + (ip->ip_hl<<2));
      c += sprintf(buf+c, "[ICMP] %s -> %s %u(%u)", src, dst, icmphdr->icmp_type, icmphdr->icmp_code);
      break;
    // unknown
    default:
      c += sprintf(buf+c, "[%d] %s -> %s", ip->ip_p, src, dst);
      break;
  }
  c += sprintf(buf+c, " (ip$=%x)", in_cksum_hdr(ip));
  if (ip->ip_p == IPPROTO_TCP) c += sprintf(buf+c, " (tcp$=%x)", tcp_cksum(ip, tcphdr, ip->ip_len));
  return buf;
}
// ====================================================================
int read_packet(int sock) {
  int			recv_bytes;
  int			addr_size;
  struct ip		*ip;
  // read socket
  addr_size = sizeof addr;
  recv_bytes = recvfrom(sock, pbuf, sizeof pbuf, 0, (struct sockaddr*)&addr, &addr_size);
  if (recv_bytes == -1) {
    if (errno == EAGAIN) return;
    dprintf("Read failed, error #%d: %s\n", errno, strerror(errno));
    return;
  }
  // get IP header 
  ip = (struct ip*)pbuf;
  pdir = (addr.sin_addr.s_addr == INADDR_ANY) ? OUTPUT : INPUT;
  // dump it
  dprintf("Incoming packet: %s\n", print_packet(buf, ip));
  // rewrite
  do_rewrite(ip);
  // dump it
  dprintf("      rewritten: %s\n", print_packet(buf, ip));
  // write to socket
  plen = ntohs(ip->ip_len);
  sending = sock;
  write_packet(sock);
}
// ====================================================================
int write_packet(int sock) {
  int			sent_bytes;
  // sending
  sent_bytes = sendto(sock, pbuf, plen, 0, (struct sockaddr*)&addr, sizeof addr);
  if (sent_bytes != plen) {
    // will wait till buffer is free
    if (errno == ENOBUFS) return;
    else dprintf("Failed to write packet, error #%d: %s\n", errno, strerror(errno));
  }
  sending = -1;
}
// ====================================================================
int main(int argc, char *argv[]) {
  int			i;
  int			flags;
  int			daemonize = 0;
  fd_set		read_mask, write_mask;
  char			*perl_file = NULL;
  char			*err_ptr;
  // parse command-line
  for (i = 1; i < argc; i++) {
    if ( strcmp(argv[i], "-d") == 0 ) daemonize = 1;
    if ( strcmp(argv[i], "-P") == 0 ) {
      port = strtol(argv[++i], &err_ptr, 10);
      if (*err_ptr != '\0') { fprintf(stderr, "Invalid port: %s (%d)\n", argv[i], err_ptr-argv[i]); exit(1); }
    }
    if ( strcmp(argv[i], "-l") == 0 ) log_file = argv[++i];
    if ( strcmp(argv[i], "-p") == 0 ) pid_file = argv[++i];
    if ( strcmp(argv[i], "-v") == 0 ) verbose = 1;
    if ( strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0 ) { puts(VERSION); exit(0); }
    if ( strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0 ) { puts(USAGE); exit(0); }
#ifdef WITH_PERL
    if ( strcmp(argv[i], "-f") == 0 ) perl_file = argv[++i];
#endif
  }
#ifdef WITH_PERL
  if (perl_file != NULL)
    if (!perl_init(perl_file)) { fprintf(stderr, "Can't init perl interpreter for file %s\n", perl_file); exit(1); }
#endif
  // daemonize
  if (daemonize) {
    daemon(0, 0);
    LOG = fopen(log_file, "a");
    PID = fopen(pid_file, "w");
    fprintf(PID, "%d\n", getpid());
    fclose(PID);
  }
  // create a socket
  sock = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
  if (sock < 0) {
    dprintf("Can't create socket, error #%d: %s\n", errno, strerror(errno));
    exit(1);
  }
  //flags = fcntl(sock, F_GETFL);
  //flags |= O_NONBLOCK;
  //fcntl(sock, F_SETFL, flags);
  // bind socket to address:port
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);
  if (bind(sock, (struct sockaddr*)&addr, sizeof addr) == -1) {
    dprintf("Can't bind to port %d, error #%d: %s\n", addr.sin_port, errno, strerror(errno));
    exit(1);
  }
  // main loop
  dprintf("Starting iprd on port %d\n", port);
  siginterrupt(SIGTERM, 1);
  siginterrupt(SIGINT,  1);
  signal(SIGTERM, sigterm_handler);
  signal(SIGINT,  sigterm_handler);
  shutdown_req = 0; sending = -1;
  while (1) {
    // check if can shutdown, or shutdown after 10sec after request
    if (shutdown_req) {
      if (sending == -1) break;
      else if (time(NULL)-shutdown_req > 10) break;
    }
    // clear masks
    FD_ZERO(&read_mask); FD_ZERO(&write_mask);
    // set mask for writing if have something to send
    if (sending != -1) FD_SET(sending, &write_mask);
    // set mask for reading if nothing to send
      else FD_SET(sock, &read_mask);
    // try to find out, is anything to do
    if (select(sock+1, &read_mask, &write_mask, NULL, NULL) == -1) {
      if (errno != EINTR)
        dprintf("Select failed, error #%d: %s\n", errno, strerror(errno));
      continue;
    }
    // if can send unsent data
    if (sending != -1 && FD_ISSET(sending, &write_mask)) write_packet(sending);
    // if data available to read
    if (FD_ISSET(sock, &read_mask)) read_packet(sock);
  }
  // close files
#ifdef WITH_PERL
  perl_done();
#endif
  if (daemonize) {
    fclose(LOG);
    unlink(pid_file);
  }
}

// ====================================================================
void do_rewrite(struct ip *ip) {
  in_addr_t		dst_ip, src_ip;
  struct tcphdr		*tcphdr;
  static short		src_port = 0;
  int i;
  //
  modified = 0;
  src_ip = inet_addr("127.0.0.1");
  dst_ip = inet_addr("127.0.0.1");
  if (ip->ip_p == IPPROTO_TCP)
    tcphdr = (struct tcphdr*) ((char*)ip + (ip->ip_hl<<2));
#if 0
  if ( /*(ip->ip_src.s_addr == src_ip) && (ip->ip_dst.s_addr == dst_ip)*/ 1) {
    if (ip->ip_p == IPPROTO_TCP) {
      tcphdr = (struct tcphdr*) ((char*)ip + (ip->ip_hl<<2));
      // if 127.0.0.1:xxx->127.0.0.1:9925 - save original port
      if ( ntohs(tcphdr->th_dport) == 9925 && pdir == OUTPUT ) {
        src_port = ntohs(tcphdr->th_sport);
	tcphdr->th_sport = htons(7000);
	tcphdr->th_dport = htons(25);
	ip->ip_src.s_addr = inet_addr("127.0.0.1");
	modified = 1;
      }
      // if 127.0.0.1:25->127.0.0.1:7000 - restore original port
      if ( ntohs(tcphdr->th_sport) == 25 && 
           ntohs(tcphdr->th_dport) == 7000 &&
	   src_port > 0 ) {
	tcphdr->th_sport = htons(9925);
	tcphdr->th_dport = htons(src_port);
	ip->ip_dst.s_addr = inet_addr("10.0.0.11");
	modified = 1;
      }
    }
  }
#endif
#ifdef WITH_PERL
  perl_exec(ip);
#endif
      // update checksums if modified
      if (modified) {
        i = ntohs(ip->ip_sum) + ntohs(in_cksum_hdr(ip));
	ip->ip_sum = htons( i > 0xffff ? ++i - 0x10000 : i );
	// some strange stuff w/tcp cksum: need to add carry flag?
        if (ip->ip_p == IPPROTO_TCP) {
	  i = ntohs(tcphdr->th_sum) + ntohs(tcp_cksum(ip, tcphdr, ip->ip_len));
	  tcphdr->th_sum = htons( i > 0xffff ? ++i - 0x10000 : i );
        }      
      }
}
// ====================================================================
static void sigterm_handler(int sig) {
  if (!shutdown_req) {
    shutdown_req = time(NULL);
    dprintf("Shutdown initiated at %s", ctime(&shutdown_req));
  }
}
