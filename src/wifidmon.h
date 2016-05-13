


void 	test(void);
void	getsock(int);
void 	print_string(const u_int8_t *, int);
void	get_device_type(struct device *);
void	parseConfigFile(struct configReq *);
int		parseLKC(void);
int 	file_exists(const char *);
int		getNetworks(char *, struct networkReq *);
void	getDevices(struct deviceReq *);
void	setnwid(char *, char *);
void	setnwidWPA(char *, char *, char *);
int		IFCHECK(char *, struct deviceReq *);
int		resolve(struct configReq *, struct deviceReq *);
int		callDHCP(char *);
int		staticAssign(void);
int		af = AF_INET;
int 	s;
int 	startUp_FLAG = 0;
int 	NETCHECK(char *, struct networkReq *);
void 	format_name(char *);
void 	log_message(char *, char *);
int		isActive(void);
void 	writeToLKC(void);
int 	setLKCInfo(char *);
int 	getSignalStrength(char *);
void 	rightInitialConfig(void);
void	logServer(char *);