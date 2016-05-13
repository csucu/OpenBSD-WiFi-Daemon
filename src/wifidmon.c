/**
 *
 *
 *
 * Author Ceysun Sucu
 *
 *
 *
 *
 **/

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>

#include <netdb.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <net/if_types.h>
#include <net/if_media.h>
#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>
#include <string.h>
#include <ctype.h>
#include <sha1.h>
#include <netinet/if_ether.h>


#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#define RUNNING_DIR	"/etc/DMON"
#define LOCK_FILE	"exampled.lock"
#define LOG_FILE	"exampled.log"
#define CONFIG_FILE	"wifidaemon.config"
#define LKC_FILE	"lkc.conf"

#define MAX_LINE_LEN 256
#define MAX_DEVICES 20
#define MAX_NETWORKS 50
#define MAX_IFSIZE 20
#define MAX_NODESIZE 20

struct network
{
	char name[20];
	char key[20];
	char bssid[20];
	u_int8_t rssi;

};
struct device
{
	char name[10];
	char type[10];
};
struct configReq
{
	struct network networks[20];
	struct device devices[MAX_DEVICES];
	int device_cnt;
	int network_cnt;
};
struct deviceReq
{
	struct device devices[MAX_DEVICES];
	int device_cnt;
};
struct networkReq
{

	struct network networks[MAX_NETWORKS];
	int network_cnt;
};

const struct ifmedia_description ifm_type_descriptions[] = IFM_TYPE_DESCRIPTIONS;
const struct if_status_description if_status_descriptions[] = LINK_STATE_DESCRIPTIONS;
const char *get_linkstate(int, int);
const char *get_string(const char *, const char *, u_int8_t *, int *);
static void hmac_sha1(const u_int8_t *text, size_t text_len, const u_int8_t *key, size_t key_len, u_int8_t digest[SHA1_DIGEST_LENGTH]);
int pkcs5_pbkdf2(const char *, size_t, const char *, size_t, u_int8_t *, size_t, u_int);

char *currentDevice;
/* All last known configuration variables */
struct device lkDevice;
struct network lkNetwork;
char  lkAddrs[256];
int lkDefaultRoute;
char lknetmask[256];
int lkc_flag = 0;

/**
 * @brief writes a message to a file
 * @param name of the file and the message that is to be writtento it
 *
 * */
void log_message(char *filename, char *message)
{
	FILE *logfile;
	logfile = fopen(filename, "a");
	if (!logfile) return;
	fprintf(logfile, "%s\n", message);
	fclose(logfile);
}

void signal_handler(sig)
int sig;
{
	switch (sig) {
	case SIGHUP:
		log_message(LOG_FILE, "hangup signal catched");
		break;
	case SIGTERM:
		log_message(LOG_FILE, "terminate signal catched");
		exit(0);
		break;
	}
}



/**
 * @brief turns the process into a daemon
 *
 * */
void daemonize()
{
	int i, lfp;
	char str[10];
	if (getppid() == 1) return;
	i = fork();
	if (i<0) exit(1);
	if (i>0) exit(0);

	setsid();
	for (i = getdtablesize(); i >= 0; --i) close(i);
	i = open("/dev/null", O_RDWR); dup(i); dup(i);
	umask(027);
	chdir(RUNNING_DIR);
	lfp = open(LOCK_FILE, O_RDWR | O_CREAT, 0640);
	if (lfp < 0) exit(1);
	if (lockf(lfp, F_TLOCK, 0) < 0) exit(0);

	sprintf(str, "%d\n", getpid());
	write(lfp, str, strlen(str));
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGHUP, signal_handler);
	signal(SIGTERM, signal_handler);
}

main()
{
	daemonize();
	while (1)
	{
		if (!file_exists(CONFIG_FILE))
		{
			rightInitialConfig();
		}
		if (isActive() != 0)
		{
			//this branch is entered on first boot, to use last used config if present
			if ((!file_exists(LKC_FILE)) && (startUp_FLAG == 0))
			{
				parseLKC();
				if (strlen(lkNetwork.key) > 0)
				{
					getsock(af);
					setnwidWPA(lkDevice.name, lkNetwork.name, lkNetwork.key);
				}
				else
				{
					setnwid(lkDevice.name, lkNetwork.name);
				}
				staticAssign();
			}
			else
			{
				struct configReq cr;
				struct deviceReq dr;
				struct networkReq nr;
				dr.device_cnt = 0;
				getDevices(&dr);
				parseConfigFile(&cr);
				resolve(&cr, &dr);
				setLKCInfo(currentDevice);
				logServer("completed loop");
			}
			writeToLKC();
			startUp_FLAG = 1;
		}
		sleep(5);
	}
}

/**
 * @brief checks if a network is active or not
 * @return  0 if network is active
 * 			1 if network is not active
 *
 * */
int isActive()
{
	struct ifreq ifr;
	struct ifaddrs *ifaddr;
	struct if_data *ifdata;
	struct ifmediareq ifmr;
	const struct ifmedia_description *desc;
	struct sockaddr_dl *sdl;
	const char *name;
	int family, type;

	if (getifaddrs(&ifaddr) == -1) {
		//perror("getifaddrs failed");
		exit(1);
	}

	struct ifaddrs *ifa = ifaddr;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr != NULL)
		{
			int family = ifa->ifa_addr->sa_family;

			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			ifdata = ifa->ifa_data;
			if (sdl->sdl_type == IFT_ETHER)
			{
				getsock(af);
				if (strcmp(get_linkstate(sdl, ifdata->ifi_link_state), "active") == 0)
					return 0;
			}
		}
	}

	freeifaddrs(ifaddr);
	return 1;
}

/**
 * @brief gets the link state
 * @return 'active' or 'not active'
 *
 * */
const char *get_linkstate(int mt, int link_state)
{
	const struct if_status_description *p;
	static char buf[8];

	for (p = if_status_descriptions; p->ifs_string != NULL; p++)
	{
		if (LINK_STATE_DESC_MATCH(p, mt, link_state))
		{
			return (p->ifs_string);
		}
	}
	snprintf(buf, sizeof(buf), "[#%d]", link_state);
	return buf;
}

/**
 * @brief calls the systems dhcp client
 * @param name of the device being configured
 *
 * */
int callDHCP(char *name)
{
	char buf[256];
	int res;

	snprintf(buf, sizeof buf, "dhclient %s", name);
	res = system(buf);

	return res;
}

/**
 * @brief configures device for a non encrypted network
 * @param char name - name of device
 * 	      char nwidName - network id
 *
 * */
void setnwid(char *name, char *nwidName)
{
	struct ifreq ifr;
	int d = 0;
	struct ieee80211_nwid nwid;
	int len;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0)
		logServer("SIOCGIFFLAGS");

	ifr.ifr_flags |= IFF_UP;

	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) != 0)
		logServer("SIOCSIFFLAGS");

	len = sizeof(nwid.i_nwid);
	if (get_string(nwidName, NULL, nwid.i_nwid, &len) == NULL)
		return;

	nwid.i_len = len;
	ifr.ifr_data = (caddr_t)&nwid;
	if (ioctl(s, SIOCS80211NWID, (caddr_t)&ifr) < 0)
		logServer("SIOCS80211NWID");
}

/**
 * @brief configures device for a WPA encrypted network
 * @param char name - name of device
 * 	      char nwidName - network id
 * 		  char wpakey - unhashed passphrase
 * */
void setnwidWPA(char *name, char *nwidName, char *wpakey)
{
	struct ifreq ifr;
	struct ieee80211_nwid nwid1;

	int d = 0;
	int len;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0)
		logServer("SIOCGIFFLAGS");

	ifr.ifr_flags |= IFF_UP;


	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) != 0)
		logServer("SIOCSIFFLAGS");

	len = sizeof(nwid1.i_nwid);
	if (get_string(nwidName, NULL, nwid1.i_nwid, &len) == NULL)
		return;

	nwid1.i_len = len;
	ifr.ifr_data = (caddr_t)&nwid1;
	if (ioctl(s, SIOCS80211NWID, (caddr_t)&ifr) < 0)
		logServer("SIOCS80211NWID");

	// set wpa	
	struct ieee80211_wpaparams wpa;

	memset(&wpa, 0, sizeof(wpa));
	(void)strlcpy(wpa.i_name, name, sizeof(wpa.i_name));
	if (ioctl(s, SIOCG80211WPAPARMS, (caddr_t)&wpa) < 0)
		logServer("SIOCG80211WPAPARMS");
	wpa.i_enabled = 0;
	if (ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa) < 0)
		logServer("SIOCS80211WPAPARMS");

	// set wpakey

	struct ieee80211_wpaparams wpa2;
	struct ieee80211_wpapsk psk;
	struct ieee80211_nwid nwid;
	int passlen;

	memset(&psk, 0, sizeof(psk));
	if (d != -1) {
		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_data = (caddr_t)&nwid;
		strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
		if (ioctl(s, SIOCG80211NWID, (caddr_t)&ifr))
			logServer("SIOCG80211NWID");

		passlen = strlen(wpakey);
		if (passlen == 2 + 2 * sizeof(psk.i_psk) && wpakey[0] == '0' && wpakey[1] == 'x')
		{
			/* Parse a WPA hex key (must be full-length) */
			passlen = sizeof(psk.i_psk);
			wpakey = get_string(wpakey, NULL, psk.i_psk, &passlen);
			if (wpakey == NULL || passlen != sizeof(psk.i_psk))
				logServer("wpakey: invalid pre-shared key");
		}
		else
		{
			/* Parse a WPA passphrase */
			if (passlen < 8 || passlen > 63)
				logServer("wpakey: passphrase must be between 8 and 63 characters");
			if (nwid.i_len == 0)
				log_message(LOG_FILE, "wpakey: nwid not set");
			if (pkcs5_pbkdf2(wpakey, passlen, nwid.i_nwid, nwid.i_len,
				psk.i_psk, sizeof(psk.i_psk), 4096) != 0)
				logServer("wpakey: passphrase hashing failed");
		}
		psk.i_enabled = 1;
	}
	else
		psk.i_enabled = 0;

	(void)strlcpy(psk.i_name, name, sizeof(psk.i_name));
	if (ioctl(s, SIOCS80211WPAPSK, (caddr_t)&psk) < 0)
		logServer("SIOCS80211WPAPSK");

	/* And ... automatically enable or disable WPA */
	memset(&wpa2, 0, sizeof(wpa2));
	(void)strlcpy(wpa2.i_name, name, sizeof(wpa2.i_name));
	if (ioctl(s, SIOCG80211WPAPARMS, (caddr_t)&wpa2) < 0)
		logServer("SIOCG80211WPAPARMS");
	wpa2.i_enabled = psk.i_enabled;
	if (ioctl(s, SIOCS80211WPAPARMS, (caddr_t)&wpa2) < 0)
		logServer("SIOCS80211WPAPARMS");
}

/**
 * @brief This method is used to resolve a applicable configuration
 * @param cr - contains are parsed configuration file
 * 	      dr - contains a list of devices
 *
 * */
int resolve(struct configReq *cr, struct deviceReq *dr)
{
	char name[MAX_IFSIZE];
	struct networkReq nr;
	int b_flag = 0;
	int i;
	nr.network_cnt = 0;
	int res = 8;
	for (i = 0; i < dr->device_cnt; i++) //??????? should b cr  for all devices 
	{
		if (IFCHECK((char *)cr->devices[i].name, dr) == 0){ // each REAL config device which
			format_name(cr->devices[i].name);
			if (res = getNetworks(cr->devices[i].name, &nr) == 0)
			{ // if getnetworks works
				//now try and setnwid to all REAL networks in cr one by one until setwid returns succsess
				b_flag = 1;
				strcpy(name, cr->devices[i].name);
				currentDevice = cr->devices[i].name;
				break;
			}
		}
	}

	char buf[256];
	if (b_flag == 1)
	{
		for (i = 0; i < cr->network_cnt; i++)
		{
			if (NETCHECK(cr->networks[i].name, &nr) == 0)
			{
				format_name(cr->networks[i].name);

				if (strlen(cr->networks[i].key) > 0)
				{
					format_name(cr->networks[i].key);
					setnwidWPA(name, cr->networks[i].name, cr->networks[i].key);
					strcpy(lkNetwork.key, cr->networks[i].key);
				}
				else
				{
					setnwid(name, cr->networks[i].name);
				}
				strcpy(lkNetwork.name, cr->networks[i].name);
				strcpy(lkDevice.name, name);
				callDHCP(name);
				break;
			}
		}
	}
}

/**
 * @brief Scan for available access points
 * @param char name - name of device being used
 * 	           nr - struct to hold results
 * @return 1 if failed
 * */
int getNetworks(char *name, struct networkReq *nR)
{
	struct ieee80211_nodereq_all na;
	struct ieee80211_nodereq nr[512];
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0)
		logServer("SIOCGIFFLAGS");

	ifr.ifr_flags |= IFF_UP;

	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&ifr) != 0)
		logServer("SIOCSIFFLAGS");

	if (ioctl(s, SIOCS80211SCAN, (caddr_t)&ifr) != 0)
	{
		logServer("\t\tno permission to scan\n");
	}

	bzero(&na, sizeof(na));
	bzero(&nr, sizeof(nr));
	na.na_node = nr;
	na.na_size = sizeof(nr);
	strlcpy(na.na_ifname, name, sizeof(na.na_ifname));

	if (ioctl(s, SIOCG80211ALLNODES, &na) != 0)
	{
		logServer("SIOCG80211ALLNODES");
		return 1; //fail
	}

	if (!na.na_nodes)
		logServer("\t\tnone\n");
	//return 1;
	int i;

	for (i = 0; i < na.na_nodes; i++)
	{
		char netname[IEEE80211_NWID_LEN];
		memcpy(netname, nr[i].nr_nwid, IEEE80211_NWID_LEN);
		strlcpy(nR->networks[i].name, netname, sizeof(nR->networks[i].name)); //get name
		strlcpy(nR->networks[i].bssid, ether_ntoa((struct ether_addr*)nr[i].nr_bssid), sizeof(nR->networks[i].bssid));
		nR->networks[i].rssi = nr[i].nr_rssi;
		nR->network_cnt++;
	}

	return 0; //succsess	
}

/**
 * @brief gets a list of devices
 * @param dr - struct to contain list of devices
 *
 * */
void getDevices(struct deviceReq *dr)
{
	struct ifreq ifr;
	struct ifaddrs *ifaddr;
	struct if_data *ifdata;
	struct ifmediareq ifmr;
	const struct ifmedia_description *desc;
	struct sockaddr_dl *sdl;
	const char *name;
	int family, type;

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs failed");
		exit(1);
	}

	struct ifaddrs *ifa = ifaddr;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr != NULL)
		{
			family = ifa->ifa_addr->sa_family;
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (sdl->sdl_type == IFT_ETHER)
			{
				getsock(af);
				strlcpy(dr->devices[dr->device_cnt].name, ifa->ifa_name, sizeof(dr->devices[dr->device_cnt].name));
				get_device_type(&dr->devices[dr->device_cnt]);
				dr->device_cnt++;
			}
		}
	}

	freeifaddrs(ifaddr);
}

/**
 * @brief parses are last used configuration file
 * @return 0 if successful
 * */
int	parseLKC(void)
{
	lkNetwork.key[0] = 0;
	FILE* config_fp;
	config_fp = fopen(LKC_FILE, "r");
	char line[MAX_LINE_LEN + 1];

	while (fgets(line, MAX_LINE_LEN, config_fp) != NULL) //each line
	{
		if (line != NULL && line[0] != '#' && strnlen(line, MAX_LINE_LEN) > 1)
		{
			if (strncmp(line, "device:", 7) == 0)
			{
				strlcpy(lkDevice.name, &line[8], sizeof(lkDevice.name));
				format_name(lkDevice.name);
			}
			else if (strncmp(line, "network:", 8) == 0)
			{
				strlcpy(lkNetwork.name, &line[9], sizeof(lkNetwork.name));
				format_name(lkNetwork.name);
			}
			else if (strncmp(line, "key:", 4) == 0)
			{
				strlcpy(lkNetwork.key, &line[5], sizeof(lkNetwork.key));
				format_name(lkNetwork.key);
			}
			else if (strncmp(line, "netmask:", 8) == 0)
			{
				strlcpy(lknetmask, &line[9], sizeof(lknetmask));
				format_name(lknetmask);
			}
			else if (strncmp(line, "inet:", 5) == 0)
			{
				strlcpy(lkAddrs, &line[6], sizeof(lkAddrs));
				format_name(lkAddrs);
			}
		}
	}
	return 0;
}

/**
 * @brief writes the current config to the lkc file
 *
 * */
void writeToLKC(void)
{
	char buf[256];

	if (!file_exists(LKC_FILE))
	{
		remove(LKC_FILE);
	}

	snprintf(buf, sizeof buf, "device: %s", lkDevice.name);
	log_message(LKC_FILE, buf);
	snprintf(buf, sizeof buf, "network: %s", lkNetwork.name);
	log_message(LKC_FILE, buf);
	snprintf(buf, sizeof buf, "inet: %s", lkAddrs);
	log_message(LKC_FILE, buf);
	snprintf(buf, sizeof buf, "netmask: %s", lknetmask);
	log_message(LKC_FILE, buf);

	if (lkNetwork.key > 0)
	{
		snprintf(buf, sizeof buf, "key: %s", lkNetwork.key);
		log_message(LKC_FILE, buf);
	}
}

/**
 * @brief checks if a file
 * @param file that we ae checking
 *
 * */
int file_exists(const char *filename)
{
	FILE *file = fopen(filename, "r");
	if (file)
	{
		fclose(file);
		return 0; //true 
	}
	return 1; //false;
}

/**
 * @brief parses are configuration file
 * @param are struct that will hold the users configuration info
 *
 * */
void parseConfigFile(struct configReq *cr)
{
	cr->device_cnt = 0;
	cr->network_cnt = -1;

	char line[MAX_LINE_LEN + 1];
	int m_FLAG = 0;
	int i;

	FILE* config_fp;
	config_fp = fopen("wifidaemon.config", "r");

	while (fgets(line, MAX_LINE_LEN, config_fp) != NULL) //each line
	{
		if (line != NULL && line[0] != '#' && strnlen(line, MAX_LINE_LEN) > 1)
		{
			if (strncmp(line, "devices", 7) == 0)
			{
				m_FLAG = 0;
				continue;
			}
			else if (strncmp(line, "network", 7) == 0)
			{
				m_FLAG = 1;
				cr->network_cnt++;
				cr->networks[cr->network_cnt].key[0] = 0;//intitialize key[0] so we can test for empty strings
				continue;
			}
			else if (strncmp(line, "LKC on boot = true", 18) == 0)
			{
				lkc_flag = 1;
			}

			if (m_FLAG == 0) //if at a device
			{
				if (line[0] == '\t')
					strlcpy(cr->devices[cr->device_cnt].name, &line[1], sizeof(cr->devices[cr->device_cnt].name));
				cr->device_cnt++;
			}
			else if (m_FLAG == 1)
			{  //if at a network 
				i = 0;
				if (line[0] == '\t')
				{
					if (strncmp(line + 1, "name = ", 4) == 0)
					{
						i += 7;
						while (line[i] == '=' || line[i] == ' ')
							i++;
						strlcpy(cr->networks[cr->network_cnt].name, &line[i], sizeof(cr->networks[cr->network_cnt].name));
					}
					else if (strncmp(line + 1, "key = ", 3) == 0)
					{
						i += 6;
						while (line[i] == '=' || line[i] == ' ')
							i++;
						strlcpy(cr->networks[cr->network_cnt].key, &line[i], sizeof(cr->networks[cr->network_cnt].key));


					}
				}
			}
		}
	}
}

/**
 * @brief opens a socket, for are iotcl ops
 *
 * */
void getsock(int naf)
{
	static int oaf = -1;

	if (oaf == naf)
		return;
	if (oaf != -1)
		close(s);
	s = socket(naf, SOCK_DGRAM, 0);
	if (s < 0)
		oaf = -1;
	else
		oaf = naf;
}

/**
 * @brief gets device type
 * @param struct that will hold are device info
 *
 * */
void get_device_type(struct device *d)
{
	struct ifmediareq ifmr;
	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, d->name, sizeof(ifmr.ifm_name));
	getsock(af);
	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0)
		logServer("SIOCGIFMEDIA");

	if (IFM_TYPE(ifmr.ifm_current) == IFM_ETHER)
		strlcpy(d->type, "ethernet", sizeof(d->type));
	else if (IFM_TYPE(ifmr.ifm_current) == IFM_IEEE80211)
		strlcpy(d->type, "wireless", sizeof(d->type));
}

/**
 * @brief compares two interface chars
 * @param char name - name of device
 * 	      dr - are device info
 **/
int	IFCHECK(char *name, struct deviceReq *dr)
{
	int i;
	for (i = 0; i < dr->device_cnt; i++)
	{
		if (strncmp(name, dr->devices[i].name, strlen(dr->devices[i].name)) == 0)
		{
			return 0;
		}
	}
	return 1;
}

/**
 * @brief compares two network id's chars
 * @param char name - name of network
 * 	      nr - are network info
 **/
int NETCHECK(char *name, struct networkReq *nr)
{
	int i;
	for (i = 0; i < nr->network_cnt; i++)
	{
		if (strncmp(name, nr->networks[i].name, strlen(nr->networks[i].name)) == 0){
			return 0;
		}
	}
	return 1;
}

/**
 * @brief formats name into correct format, removing unwantted chars from the end of a string
 * @param char name - are string
 *
 **/
void format_name(char *name)
{
	int pos = strlen(name) - 1;
	while (!isalpha(name[pos]) && !isdigit(name[pos]))
	{
		name[pos] = 0;
		pos--;
	}
}

/**
 * @brief converts to string
 *
 *
 **/
const char *get_string(const char *val, const char *sep, u_int8_t *buf, int *lenp)
{
	int len = *lenp, hexstr;
	u_int8_t *p = buf;

	hexstr = (val[0] == '0' && tolower((u_char)val[1]) == 'x');
	if (hexstr)
		val += 2;
	for (;;) {
		if (*val == '\0')
			break;
		if (sep != NULL && strchr(sep, *val) != NULL) {
			val++;
			break;
		}
		if (hexstr) {
			if (!isxdigit((u_char)val[0]) ||
				!isxdigit((u_char)val[1])) {
				//warnx("bad hexadecimal digits");
				return NULL;
			}
		}
		if (p > buf + len) {
			if (hexstr)
				log_message(LOG_FILE, "hexadecimal digits too long");
			else
				log_message(LOG_FILE, "strings too long");
			return NULL;
		}
		if (hexstr) {
#define	tohex(x)	(isdigit(x) ? (x) - '0' : tolower(x) - 'a' + 10)
			*p++ = (tohex((u_char)val[0]) << 4) |
				tohex((u_char)val[1]);
#undef tohex
			val += 2;
		}
		else {
			if (*val == '\\' &&
				sep != NULL && strchr(sep, *(val + 1)) != NULL)
				val++;
			*p++ = *val++;
		}
	}
	len = p - buf;
	if (len < *lenp)
		memset(p, 0, *lenp - len);
	*lenp = len;
	return val;
}

int pkcs5_pbkdf2(const char *pass, size_t pass_len, const char *salt, size_t salt_len,
	u_int8_t *key, size_t key_len, u_int rounds)
{
	u_int8_t *asalt, obuf[20];
	u_int8_t d1[20], d2[20];
	u_int i, j;
	u_int count;
	size_t r;

	if (rounds < 1 || key_len == 0)
		return -1;
	if (salt_len == 0 || salt_len > SIZE_MAX - 4)
		return -1;
	if ((asalt = malloc(salt_len + 4)) == NULL)
		return -1;

	memcpy(asalt, salt, salt_len);

	for (count = 1; key_len > 0; count++) {
		asalt[salt_len + 0] = (count >> 24) & 0xff;
		asalt[salt_len + 1] = (count >> 16) & 0xff;
		asalt[salt_len + 2] = (count >> 8) & 0xff;
		asalt[salt_len + 3] = count & 0xff;
		hmac_sha1(asalt, salt_len + 4, pass, pass_len, d1);
		memcpy(obuf, d1, sizeof(obuf));

		for (i = 1; i < rounds; i++) {
			hmac_sha1(d1, sizeof(d1), pass, pass_len, d2);
			memcpy(d1, d2, sizeof(d1));
			for (j = 0; j < sizeof(obuf); j++)
				obuf[j] ^= d1[j];
		}

		r = MIN(key_len, SHA1_DIGEST_LENGTH);
		memcpy(key, obuf, r);
		key += r;
		key_len -= r;
	};
	bzero(asalt, salt_len + 4);
	free(asalt);
	bzero(d1, sizeof(d1));
	bzero(d2, sizeof(d2));
	bzero(obuf, sizeof(obuf));

	return 0;
}


static void hmac_sha1(const u_int8_t *text, size_t text_len, const u_int8_t *key,
	size_t key_len, u_int8_t digest[SHA1_DIGEST_LENGTH])
{
	SHA1_CTX ctx;
	u_int8_t k_pad[SHA1_BLOCK_LENGTH];
	u_int8_t tk[SHA1_DIGEST_LENGTH];
	int i;

	if (key_len > SHA1_BLOCK_LENGTH) {
		SHA1Init(&ctx);
		SHA1Update(&ctx, key, key_len);
		SHA1Final(tk, &ctx);

		key = tk;
		key_len = SHA1_DIGEST_LENGTH;
	}

	bzero(k_pad, sizeof k_pad);
	bcopy(key, k_pad, key_len);
	for (i = 0; i < SHA1_BLOCK_LENGTH; i++)
		k_pad[i] ^= 0x36;

	SHA1Init(&ctx);
	SHA1Update(&ctx, k_pad, SHA1_BLOCK_LENGTH);
	SHA1Update(&ctx, text, text_len);
	SHA1Final(digest, &ctx);

	bzero(k_pad, sizeof k_pad);
	bcopy(key, k_pad, key_len);
	for (i = 0; i < SHA1_BLOCK_LENGTH; i++)
		k_pad[i] ^= 0x5c;

	SHA1Init(&ctx);
	SHA1Update(&ctx, k_pad, SHA1_BLOCK_LENGTH);
	SHA1Update(&ctx, digest, SHA1_DIGEST_LENGTH);
	SHA1Final(digest, &ctx);
}


/**
 * @brief staticly assigns an IP address and default route
 *
 **/
int staticAssign(void){


	char buf[256];
	snprintf(buf, sizeof buf, "ifconfig %s inet %s netmask %s up", lkDevice.name, lkAddrs, lknetmask);
	int res;
	res = system(buf);
	system("route add default 192.168.0.1");




}
/**
 * @brief gets are ip address and netmask
 *
 **/
int setLKCInfo(char *name){


	struct ifaddrs *ifaddr, *ifa;
	int family, s;
	char host[NI_MAXHOST];
	char netmask[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1)
	{
		return 1;
	}


	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in), netmask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if ((strcmp(ifa->ifa_name, name) == 0) && (ifa->ifa_addr->sa_family == AF_INET))
		{
			if (s != 0)
			{

				return 1;
			}
			char buffr[100];
			const struct sockaddr_in *sin;
			sin = ifa->ifa_netmask;
			inet_ntop(AF_INET, &sin->sin_addr, buffr, sizeof(buffr));



			strncpy(lkAddrs, host, sizeof(lkAddrs));
			strncpy(lknetmask, buffr, sizeof(lknetmask));
			//printf("ip add: %s netmask: %s\n", lkAddrs, lknetmask);
			break;

		}
	}

	freeifaddrs(ifaddr);


}
/**
 * @brief creates a config file
 *
 * */
void rightInitialConfig(void){


	log_message(CONFIG_FILE, "# here is an example of an device listing:");
	log_message(CONFIG_FILE, "#");
	log_message(CONFIG_FILE, "# device");
	log_message(CONFIG_FILE, "#	   urtw0");
	log_message(CONFIG_FILE, "#	   rv0");
	log_message(CONFIG_FILE, "#");
	log_message(CONFIG_FILE, "#  Below is an exmaple of a network listing");
	log_message(CONFIG_FILE, "#");
	log_message(CONFIG_FILE, "# network");
	log_message(CONFIG_FILE, "#	    name = somenetworkid");
	log_message(CONFIG_FILE, "#	    key = somenetworkid");
	log_message(CONFIG_FILE, "#");
	log_message(CONFIG_FILE, "# A network listing does not need to contain a key, t is also important to note you ");
	log_message(CONFIG_FILE, "# can write as many network listings as you want.");
	log_message(CONFIG_FILE, "# remmember that the first read device or network will have the highet priority, so list");
	log_message(CONFIG_FILE, "# your individule items top- down depending on there priority");
}

/**
 * @brief logs to syslogd
 * @param message to be logged
 *
 **/

void logServer(char *msg){
	openlog("DMON", LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, msg);
	closelog();

}



